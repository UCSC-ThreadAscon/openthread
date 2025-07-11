/*
 *  Copyright (c) 2024, The OpenThread Authors.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

#include "mdns_socket.hpp"

#if OPENTHREAD_CONFIG_MULTICAST_DNS_ENABLE

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef __linux__
#include <linux/rtnetlink.h>
#endif

#include <openthread/platform/time.h>

#include "ip6_utils.hpp"
#include "platform-posix.h"
#include "utils.hpp"
#include "common/code_utils.hpp"

extern "C" otError otPlatMdnsSetListeningEnabled(otInstance *aInstance, bool aEnable, uint32_t aInfraIfIndex)
{
    return ot::Posix::MdnsSocket::Get().SetListeningEnabled(aInstance, aEnable, aInfraIfIndex);
}

extern "C" void otPlatMdnsSendMulticast(otInstance *aInstance, otMessage *aMessage, uint32_t aInfraIfIndex)
{
    OT_UNUSED_VARIABLE(aInstance);
    return ot::Posix::MdnsSocket::Get().SendMulticast(aMessage, aInfraIfIndex);
}

extern "C" void otPlatMdnsSendUnicast(otInstance *aInstance, otMessage *aMessage, const otPlatMdnsAddressInfo *aAddress)
{
    OT_UNUSED_VARIABLE(aInstance);
    return ot::Posix::MdnsSocket::Get().SendUnicast(aMessage, aAddress);
}

namespace ot {
namespace Posix {

using namespace ot::Posix::Ip6Utils;

const char MdnsSocket::kLogModuleName[] = "MdnsSocket";

MdnsSocket &MdnsSocket::Get(void)
{
    static MdnsSocket sInstance;

    return sInstance;
}

void MdnsSocket::Init(void)
{
    mEnabled      = false;
    mInfraIfIndex = 0;
    mFd6          = -1;
    mFd4          = -1;
    mPendingIp6Tx = 0;
    mPendingIp4Tx = 0;

    // mDNS multicast IPv6 address "ff02::fb"
    memset(&mMulticastIp6Address, 0, sizeof(otIp6Address));
    mMulticastIp6Address.mFields.m8[0]  = 0xff;
    mMulticastIp6Address.mFields.m8[1]  = 0x02;
    mMulticastIp6Address.mFields.m8[15] = 0xfb;

    // mDNS multicast IPv4 address "224.0.0.251"
    memset(&mMulticastIp4Address, 0, sizeof(otIp4Address));
    mMulticastIp4Address.mFields.m8[0] = 224;
    mMulticastIp4Address.mFields.m8[3] = 251;

    memset(&mTxQueue, 0, sizeof(mTxQueue));

#if OPENTHREAD_POSIX_CONFIG_MDNS_ADDR_MONITOR == OT_POSIX_MDNS_ADDR_MONITOR_NETLINK
    mNetlinkFd = -1;
#endif
}

void MdnsSocket::SetUp(void)
{
    otMessageQueueInit(&mTxQueue);
    Mainloop::Manager::Get().Add(*this);
}

void MdnsSocket::TearDown(void)
{
    Mainloop::Manager::Get().Remove(*this);

    if (mEnabled)
    {
        ClearTxQueue();
        mEnabled = false;
    }
}

void MdnsSocket::Deinit(void)
{
    CloseIp4Socket();
    CloseIp6Socket();
}

void MdnsSocket::Update(Mainloop::Context &aContext)
{
    VerifyOrExit(mEnabled);

    Mainloop::AddToReadFdSet(mFd6, aContext);
    Mainloop::AddToReadFdSet(mFd4, aContext);

    if (mPendingIp6Tx > 0)
    {
        Mainloop::AddToWriteFdSet(mFd6, aContext);
    }

    if (mPendingIp4Tx > 0)
    {
        Mainloop::AddToWriteFdSet(mFd4, aContext);
    }

#if (OPENTHREAD_POSIX_CONFIG_MDNS_ADDR_MONITOR == OT_POSIX_MDNS_ADDR_MONITOR_PERIODIC)
    UpdateTimeout(aContext);
#elif (OPENTHREAD_POSIX_CONFIG_MDNS_ADDR_MONITOR == OT_POSIX_MDNS_ADDR_MONITOR_NETLINK)
    UpdateNetlink(aContext);
#endif

exit:
    return;
}

void MdnsSocket::Process(const Mainloop::Context &aContext)
{
    VerifyOrExit(mEnabled);

    if (Mainloop::IsFdWritable(mFd6, aContext))
    {
        SendQueuedMessages(kIp6Msg);
    }

    if (Mainloop::IsFdWritable(mFd4, aContext))
    {
        SendQueuedMessages(kIp4Msg);
    }

    if (Mainloop::IsFdReadable(mFd6, aContext))
    {
        ReceiveMessage(kIp6Msg);
    }

    if (Mainloop::IsFdReadable(mFd4, aContext))
    {
        ReceiveMessage(kIp4Msg);
    }

#if (OPENTHREAD_POSIX_CONFIG_MDNS_ADDR_MONITOR == OT_POSIX_MDNS_ADDR_MONITOR_PERIODIC)
    ProcessTimeout();
#elif (OPENTHREAD_POSIX_CONFIG_MDNS_ADDR_MONITOR == OT_POSIX_MDNS_ADDR_MONITOR_NETLINK)
    ProcessNetlink(aContext);
#endif

exit:
    return;
}

otError MdnsSocket::SetListeningEnabled(otInstance *aInstance, bool aEnable, uint32_t aInfraIfIndex)
{
    otError error = OT_ERROR_NONE;

    VerifyOrExit(aEnable != mEnabled);
    mInstance = aInstance;

    if (aEnable)
    {
        error = Enable(aInfraIfIndex);
    }
    else
    {
        Disable(aInfraIfIndex);
    }

exit:
    return error;
}

otError MdnsSocket::Enable(uint32_t aInfraIfIndex)
{
    otError error;

    SuccessOrExit(error = OpenIp4Socket(aInfraIfIndex));
    SuccessOrExit(error = JoinOrLeaveIp4MulticastGroup(/* aJoin */ true, aInfraIfIndex));

    SuccessOrExit(error = OpenIp6Socket(aInfraIfIndex));
    SuccessOrExit(error = JoinOrLeaveIp6MulticastGroup(/* aJoin */ true, aInfraIfIndex));

    mEnabled      = true;
    mInfraIfIndex = aInfraIfIndex;

    StartAddressMonitoring();

    LogInfo("Enabled");

exit:
    if (error != OT_ERROR_NONE)
    {
        CloseIp4Socket();
        CloseIp6Socket();
    }

    return error;
}

void MdnsSocket::Disable(uint32_t aInfraIfIndex)
{
    ClearTxQueue();

    IgnoreError(JoinOrLeaveIp4MulticastGroup(/* aJoin */ false, aInfraIfIndex));
    IgnoreError(JoinOrLeaveIp6MulticastGroup(/* aJoin */ false, aInfraIfIndex));
    CloseIp4Socket();
    CloseIp6Socket();

    mEnabled = false;

    StopAddressMonitoring();

    LogInfo("Disabled");
}

void MdnsSocket::SendMulticast(otMessage *aMessage, uint32_t aInfraIfIndex)
{
    Metadata metadata;
    uint16_t length;

    VerifyOrExit(mEnabled);
    VerifyOrExit(aInfraIfIndex == mInfraIfIndex);

    length = otMessageGetLength(aMessage);

    if (length > kMaxMessageLength)
    {
        LogWarn("Multicast msg length %u is longer than max %u", length, kMaxMessageLength);
        ExitNow();
    }

    metadata.mIp6Address = mMulticastIp6Address;
    metadata.mIp6Port    = kMdnsPort;
    metadata.mIp4Address = mMulticastIp4Address;
    metadata.mIp4Port    = kMdnsPort;

    SuccessOrExit(otMessageAppend(aMessage, &metadata, sizeof(Metadata)));

    mPendingIp4Tx++;
    mPendingIp6Tx++;

    otMessageQueueEnqueue(&mTxQueue, aMessage);
    aMessage = NULL;

exit:
    if (aMessage != NULL)
    {
        otMessageFree(aMessage);
    }
}

void MdnsSocket::SendUnicast(otMessage *aMessage, const otPlatMdnsAddressInfo *aAddress)
{
    bool     isIp4 = false;
    Metadata metadata;
    uint16_t length;

    VerifyOrExit(mEnabled);
    VerifyOrExit(aAddress->mInfraIfIndex == mInfraIfIndex);

    length = otMessageGetLength(aMessage);

    if (length > kMaxMessageLength)
    {
        LogWarn("Unicast msg length %u is longer than max %u", length, kMaxMessageLength);
        ExitNow();
    }

    memset(&metadata, 0, sizeof(Metadata));

    if (otIp4FromIp4MappedIp6Address(&aAddress->mAddress, &metadata.mIp4Address) == OT_ERROR_NONE)
    {
        isIp4             = true;
        metadata.mIp4Port = aAddress->mPort;
        metadata.mIp6Port = 0;
    }
    else
    {
        metadata.mIp6Address = aAddress->mAddress;
        metadata.mIp4Port    = 0;
        metadata.mIp6Port    = aAddress->mPort;
    }

    SuccessOrExit(otMessageAppend(aMessage, &metadata, sizeof(Metadata)));

    if (isIp4)
    {
        mPendingIp4Tx++;
    }
    else
    {
        mPendingIp6Tx++;
    }

    otMessageQueueEnqueue(&mTxQueue, aMessage);
    aMessage = NULL;

exit:
    if (aMessage != NULL)
    {
        otMessageFree(aMessage);
    }
}

void MdnsSocket::ClearTxQueue(void)
{
    otMessage *message;

    while ((message = otMessageQueueGetHead(&mTxQueue)) != NULL)
    {
        otMessageQueueDequeue(&mTxQueue, message);
        otMessageFree(message);
    }

    mPendingIp4Tx = 0;
    mPendingIp6Tx = 0;
}

void MdnsSocket::SendQueuedMessages(MsgType aMsgType)
{
    otMessage *message;
    otMessage *nextMessage;

    switch (aMsgType)
    {
    case kIp6Msg:
        VerifyOrExit(mPendingIp6Tx > 0);
        break;
    case kIp4Msg:
        VerifyOrExit(mPendingIp4Tx > 0);
        break;
    }

    for (message = otMessageQueueGetHead(&mTxQueue); message != NULL; message = nextMessage)
    {
        bool                isTxPending = false;
        uint16_t            length;
        uint16_t            offset;
        int                 bytesSent;
        Metadata            metadata;
        uint8_t             buffer[kMaxMessageLength];
        struct sockaddr_in6 addr6;
        struct sockaddr_in  addr;

        nextMessage = otMessageQueueGetNext(&mTxQueue, message);

        length = otMessageGetLength(message);

        offset = length - sizeof(Metadata);
        length -= sizeof(Metadata);

        otMessageRead(message, offset, &metadata, sizeof(Metadata));

        switch (aMsgType)
        {
        case kIp6Msg:
            isTxPending = (metadata.mIp6Port != 0);
            break;
        case kIp4Msg:
            isTxPending = (metadata.mIp4Port != 0);
            break;
        }

        if (!isTxPending)
        {
            continue;
        }

        otMessageRead(message, 0, buffer, length);

        switch (aMsgType)
        {
        case kIp6Msg:
            memset(&addr6, 0, sizeof(addr6));
            addr6.sin6_family = AF_INET6;
            addr6.sin6_port   = htons(metadata.mIp6Port);
            CopyIp6AddressTo(metadata.mIp6Address, &addr6.sin6_addr);
            bytesSent = sendto(mFd6, buffer, length, 0, reinterpret_cast<struct sockaddr *>(&addr6), sizeof(addr6));
            VerifyOrExit(bytesSent == length);
            metadata.mIp6Port = 0;
            mPendingIp6Tx--;
            break;

        case kIp4Msg:
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port   = htons(metadata.mIp4Port);
            memcpy(&addr.sin_addr.s_addr, &metadata.mIp4Address, sizeof(otIp4Address));
            bytesSent = sendto(mFd4, buffer, length, 0, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr));
            VerifyOrExit(bytesSent == length);
            metadata.mIp4Port = 0;
            mPendingIp4Tx--;
            break;
        }

        if (metadata.CanFreeMessage())
        {
            otMessageQueueDequeue(&mTxQueue, message);
            otMessageFree(message);
        }
        else
        {
            otMessageWrite(message, offset, &metadata, sizeof(Metadata));
        }
    }

exit:
    return;
}

void MdnsSocket::ReceiveMessage(MsgType aMsgType)
{
    otMessage            *message = nullptr;
    uint8_t               buffer[kMaxMessageLength];
    otPlatMdnsAddressInfo addrInfo;
    uint16_t              length = 0;
    struct sockaddr_in6   sockaddr6;
    struct sockaddr_in    sockaddr;
    socklen_t             len = sizeof(sockaddr6);
    ssize_t               rval;

    memset(&addrInfo, 0, sizeof(addrInfo));

    switch (aMsgType)
    {
    case kIp6Msg:
        len = sizeof(sockaddr6);
        memset(&sockaddr6, 0, sizeof(sockaddr6));
        rval = recvfrom(mFd6, reinterpret_cast<char *>(&buffer), sizeof(buffer), 0,
                        reinterpret_cast<struct sockaddr *>(&sockaddr6), &len);
        VerifyOrExit(rval >= 0, LogCrit("recvfrom() for IPv6 socket failed, errno: %s", strerror(errno)));
        length = static_cast<uint16_t>(rval);
        ReadIp6AddressFrom(&sockaddr6.sin6_addr, addrInfo.mAddress);
        break;

    case kIp4Msg:
        len = sizeof(sockaddr);
        memset(&sockaddr, 0, sizeof(sockaddr));
        rval = recvfrom(mFd4, reinterpret_cast<char *>(&buffer), sizeof(buffer), 0,
                        reinterpret_cast<struct sockaddr *>(&sockaddr), &len);
        VerifyOrExit(rval >= 0, LogCrit("recvfrom() for IPv4 socket failed, errno: %s", strerror(errno)));
        length = static_cast<uint16_t>(rval);
        otIp4ToIp4MappedIp6Address((otIp4Address *)(&sockaddr.sin_addr.s_addr), &addrInfo.mAddress);
        break;
    }

    VerifyOrExit(length > 0);

    message = otIp6NewMessage(mInstance, nullptr);
    VerifyOrExit(message != nullptr);
    SuccessOrExit(otMessageAppend(message, buffer, length));

    addrInfo.mPort         = kMdnsPort;
    addrInfo.mInfraIfIndex = mInfraIfIndex;

    otPlatMdnsHandleReceive(mInstance, message, /* aInUnicast */ false, &addrInfo);
    message = nullptr;

exit:
    if (message != nullptr)
    {
        otMessageFree(message);
    }
}

//---------------------------------------------------------------------------------------------------------------------
// Monitoring address on infra netif

void MdnsSocket::ReportInfraIfAddresses(void)
{
    struct ifaddrs *ifAddrs = nullptr;

#if (OPENTHREAD_POSIX_CONFIG_MDNS_ADDR_MONITOR == OT_POSIX_MDNS_ADDR_MONITOR_PERIODIC)
    mNextReportTime = otPlatTimeGet() + kAddrMonitorPeriod * OT_US_PER_MS;
#endif

    if (getifaddrs(&ifAddrs) < 0)
    {
        LogWarn("Failed to get netif addresses: %s", strerror(errno));
        ExitNow();
    }

    otPlatMdnsHandleHostAddressRemoveAll(mInstance, mInfraIfIndex);

    for (struct ifaddrs *addr = ifAddrs; addr != nullptr; addr = addr->ifa_next)
    {
        otIp6Address ip6Addr;
        otIp4Address ip4Addr;

        if ((addr->ifa_addr == nullptr) || (if_nametoindex(addr->ifa_name) != mInfraIfIndex))
        {
            continue;
        }

        if (addr->ifa_addr->sa_family == AF_INET6)
        {
            ReadIp6AddressFrom(&reinterpret_cast<sockaddr_in6 *>(addr->ifa_addr)->sin6_addr, ip6Addr);
        }
        else if (addr->ifa_addr->sa_family == AF_INET)
        {
            memcpy(&ip4Addr, &reinterpret_cast<sockaddr_in *>(addr->ifa_addr)->sin_addr.s_addr, sizeof(otIp4Address));
            otIp4ToIp4MappedIp6Address(&ip4Addr, &ip6Addr);
        }
        else
        {
            continue;
        }

        otPlatMdnsHandleHostAddressEvent(mInstance, &ip6Addr, /* aAdded */ true, mInfraIfIndex);
    }

exit:
    if (ifAddrs != nullptr)
    {
        freeifaddrs(ifAddrs);
    }
}

#if (OPENTHREAD_POSIX_CONFIG_MDNS_ADDR_MONITOR == OT_POSIX_MDNS_ADDR_MONITOR_PERIODIC)

void MdnsSocket::StartAddressMonitoring(void) { ReportInfraIfAddresses(); }

void MdnsSocket::StopAddressMonitoring(void) {}

void MdnsSocket::UpdateTimeout(Mainloop::Context &aContext)
{
    uint64_t now       = otPlatTimeGet();
    uint64_t remaining = 1;

    if (mNextReportTime > now)
    {
        remaining = mNextReportTime - now;
    }

    Mainloop::SetTimeoutIfEarlier(remaining, aContext);
}

void MdnsSocket::ProcessTimeout(void)
{
    if (mNextReportTime <= otPlatTimeGet())
    {
        ReportInfraIfAddresses();
    }
}

#endif // (OPENTHREAD_POSIX_CONFIG_MDNS_ADDR_MONITOR == OT_POSIX_MDNS_ADDR_MONITOR_PERIODIC)

//- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#if (OPENTHREAD_POSIX_CONFIG_MDNS_ADDR_MONITOR == OT_POSIX_MDNS_ADDR_MONITOR_NETLINK)

void MdnsSocket::StartAddressMonitoring(void)
{
    int                rval;
    struct sockaddr_nl addr;

    mNetlinkFd = SocketWithCloseExec(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE, kSocketBlock);
    VerifyOrDie(mNetlinkFd >= 0, OT_EXIT_ERROR_ERRNO);

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;

    rval = bind(mNetlinkFd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr));
    VerifyOrDie(rval == 0, OT_EXIT_ERROR_ERRNO);

    ReportInfraIfAddresses();
}

void MdnsSocket::StopAddressMonitoring(void)
{
    if (mNetlinkFd >= 0)
    {
        close(mNetlinkFd);
    }

    mNetlinkFd = -1;
}

void MdnsSocket::UpdateNetlink(Mainloop::Context &aContext) const { Mainloop::AddToReadFdSet(mNetlinkFd, aContext); }

void MdnsSocket::ProcessNetlink(const Mainloop::Context &aContext) const
{
    static const size_t kBufSize = 8192;

    union NetlinkMessage
    {
        struct nlmsghdr mHeader;
        uint8_t         mBuffer[kBufSize];
    };

    NetlinkMessage rcvMsg;
    ssize_t        rval;
    size_t         len;

    VerifyOrExit(mNetlinkFd >= 0);

    VerifyOrExit(Mainloop::IsFdReadable(mNetlinkFd, aContext));

    rval = recv(mNetlinkFd, rcvMsg.mBuffer, sizeof(rcvMsg.mBuffer), 0);

    if (rval < 0)
    {
        LogCrit("Failed to receive netlink message: %s", strerror(errno));
        ExitNow();
    }

    VerifyOrExit(static_cast<size_t>(rval) <= sizeof(rcvMsg.mBuffer));

    len = static_cast<size_t>(rval);

    VerifyOrExit(len >= sizeof(nlmsghdr));

    for (struct nlmsghdr *msg = &rcvMsg.mHeader; NLMSG_OK(msg, len); msg = NLMSG_NEXT(msg, len))
    {
        switch (msg->nlmsg_type)
        {
        case RTM_NEWADDR:
        case RTM_DELADDR:
            ProcessNetlinkAddrEvent(msg);
            break;
        case NLMSG_ERROR:
            LogWarn("netlink error:%d", reinterpret_cast<struct nlmsgerr *>(NLMSG_DATA(msg))->error);
            break;
        case NLMSG_DONE:
            ExitNow();
        }
    }

exit:
    return;
}

void MdnsSocket::ProcessNetlinkAddrEvent(void *aNetlinkMsg) const
{
    struct nlmsghdr  *msg     = static_cast<struct nlmsghdr *>(aNetlinkMsg);
    struct ifaddrmsg *addrmsg = reinterpret_cast<struct ifaddrmsg *>(NLMSG_DATA(msg));
    bool              added   = (msg->nlmsg_type == RTM_NEWADDR);
    size_t            len;
    struct rtattr    *rta;
    otIp6Address      ip6Addr;
    otIp4Address      ip4Addr;

    VerifyOrExit(addrmsg->ifa_index == mInfraIfIndex);

    switch (addrmsg->ifa_family)
    {
    case AF_INET6:
    case AF_INET:
        break;
    default:
        ExitNow();
    }

    len = IFA_PAYLOAD(msg);

    for (rta = reinterpret_cast<struct rtattr *>(IFA_RTA(addrmsg)); RTA_OK(rta, len); rta = RTA_NEXT(rta, len))
    {
        switch (rta->rta_type)
        {
        case IFA_ADDRESS:
        case IFA_LOCAL:
            if (addrmsg->ifa_family == AF_INET6)
            {
                if (RTA_PAYLOAD(rta) < sizeof(otIp6Address))
                {
                    continue;
                }

                ReadIp6AddressFrom(RTA_DATA(rta), ip6Addr);
            }
            else
            {
                if (RTA_PAYLOAD(rta) < sizeof(otIp4Address))
                {
                    continue;
                }

                memcpy(&ip4Addr, RTA_DATA(rta), sizeof(otIp4Address));
                otIp4ToIp4MappedIp6Address(&ip4Addr, &ip6Addr);
            }

            otPlatMdnsHandleHostAddressEvent(mInstance, &ip6Addr, added, mInfraIfIndex);
            break;
        }
    }

exit:
    return;
}

#endif //  (OPENTHREAD_POSIX_CONFIG_MDNS_ADDR_MONITOR == OT_POSIX_MDNS_ADDR_MONITOR_NETLINK)

//---------------------------------------------------------------------------------------------------------------------
// Socket helpers

otError MdnsSocket::OpenIp4Socket(uint32_t aInfraIfIndex)
{
    otError            error = OT_ERROR_FAILED;
    struct sockaddr_in addr;
    int                fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    VerifyOrExit(fd >= 0, LogCrit("Failed to create IPv4 socket"));

#ifdef __linux__
    {
        char        nameBuffer[IF_NAMESIZE];
        const char *ifname;

        ifname = if_indextoname(aInfraIfIndex, nameBuffer);
        VerifyOrExit(ifname != NULL, LogCrit("if_indextoname() failed"));

        error = SetSocketOptionValue(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname), "SO_BINDTODEVICE");
        SuccessOrExit(error);
    }
#else
    {
        int ifindex = static_cast<int>(aInfraIfIndex);

        SuccessOrExit(error = SetSocketOption<int>(fd, IPPROTO_IP, IP_BOUND_IF, ifindex, "IP_BOUND_IF"));
    }
#endif

    SuccessOrExit(error = SetSocketOption<uint8_t>(fd, IPPROTO_IP, IP_MULTICAST_TTL, 255, "IP_MULTICAST_TTL"));
    SuccessOrExit(error = SetSocketOption<int>(fd, IPPROTO_IP, IP_TTL, 255, "IP_TTL"));
    SuccessOrExit(error = SetSocketOption<uint8_t>(fd, IPPROTO_IP, IP_MULTICAST_LOOP, 1, "IP_MULTICAST_LOOP"));
    SuccessOrExit(error = SetReuseAddrPortOptions(fd));

    {
        struct ip_mreqn mreqn;

        memset(&mreqn, 0, sizeof(mreqn));
        mreqn.imr_multiaddr.s_addr = inet_addr("224.0.0.251");
        mreqn.imr_ifindex          = aInfraIfIndex;

        SuccessOrExit(
            error = SetSocketOptionValue(fd, IPPROTO_IP, IP_MULTICAST_IF, &mreqn, sizeof(mreqn), "IP_MULTICAST_IF"));
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons(kMdnsPort);

    if (bind(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0)
    {
        LogCrit("bind() to mDNS port for IPv4 socket failed, errno: %s", strerror(errno));
        error = OT_ERROR_FAILED;
        ExitNow();
    }

    mFd4 = fd;

    LogInfo("Successfully opened IPv4 socket");

exit:
    return error;
}

otError MdnsSocket::JoinOrLeaveIp4MulticastGroup(bool aJoin, uint32_t aInfraIfIndex)
{
    struct ip_mreqn mreqn;

    memset(&mreqn, 0, sizeof(mreqn));
    memcpy(&mreqn.imr_multiaddr.s_addr, &mMulticastIp4Address, sizeof(otIp4Address));
    mreqn.imr_ifindex = aInfraIfIndex;

    if (aJoin)
    {
        // Suggested workaround for netif not dropping
        // a previous multicast membership.
        setsockopt(mFd4, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreqn, sizeof(mreqn));
    }

    return SetSocketOption(mFd4, IPPROTO_IP, aJoin ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP, mreqn,
                           "IP_ADD/DROP_MEMBERSHIP");
}

void MdnsSocket::CloseIp4Socket(void)
{
    if (mFd4 >= 0)
    {
        close(mFd4);
        mFd4 = -1;
    }
}

otError MdnsSocket::OpenIp6Socket(uint32_t aInfraIfIndex)
{
    otError             error = OT_ERROR_FAILED;
    struct sockaddr_in6 addr6;
    int                 fd;
    int                 ifindex = static_cast<int>(aInfraIfIndex);

    fd = socket(AF_INET6, SOCK_DGRAM, 0);
    VerifyOrExit(fd >= 0, LogCrit("Failed to create IPv4 socket"));

#ifdef __linux__
    {
        char        nameBuffer[IF_NAMESIZE];
        const char *ifname;

        ifname = if_indextoname(aInfraIfIndex, nameBuffer);
        VerifyOrExit(ifname != NULL, LogCrit("if_indextoname() failed"));

        error = SetSocketOptionValue(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname), "SO_BINDTODEVICE");
        SuccessOrExit(error);
    }
#else
    {
        SuccessOrExit(error = SetSocketOption<int>(fd, IPPROTO_IPV6, IPV6_BOUND_IF, ifindex, "IPV6_BOUND_IF"));
    }
#endif

    SuccessOrExit(error = SetSocketOption<int>(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, 255, "IPV6_MULTICAST_HOPS"));
    SuccessOrExit(error = SetSocketOption<int>(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, 255, "IPV6_UNICAST_HOPS"));
    SuccessOrExit(error = SetSocketOption<int>(fd, IPPROTO_IPV6, IPV6_V6ONLY, 1, "IPV6_V6ONLY"));
    SuccessOrExit(error = SetSocketOption<int>(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, ifindex, "IPV6_MULTICAST_IF"));
    SuccessOrExit(error = SetSocketOption<int>(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, 1, "IPV6_MULTICAST_LOOP"));
    SuccessOrExit(error = SetReuseAddrPortOptions(fd));

    memset(&addr6, 0, sizeof(addr6));
    addr6.sin6_family = AF_INET6;
    addr6.sin6_port   = htons(kMdnsPort);

    if (bind(fd, reinterpret_cast<struct sockaddr *>(&addr6), sizeof(addr6)) < 0)
    {
        LogCrit("bind() to mDNS port for IPv6 socket failed, errno: %s", strerror(errno));
        error = OT_ERROR_FAILED;
        ExitNow();
    }

    mFd6 = fd;

    LogInfo("Successfully opened IPv6 socket");

exit:
    return error;
}

#ifndef IPV6_ADD_MEMBERSHIP
#ifdef IPV6_JOIN_GROUP
#define IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP
#endif
#endif

#ifndef IPV6_DROP_MEMBERSHIP
#ifdef IPV6_LEAVE_GROUP
#define IPV6_DROP_MEMBERSHIP IPV6_LEAVE_GROUP
#endif
#endif

otError MdnsSocket::JoinOrLeaveIp6MulticastGroup(bool aJoin, uint32_t aInfraIfIndex)
{
    struct ipv6_mreq mreq6;

    memset(&mreq6, 0, sizeof(mreq6));
    Ip6Utils::CopyIp6AddressTo(mMulticastIp6Address, &mreq6.ipv6mr_multiaddr);

    mreq6.ipv6mr_interface = static_cast<int>(aInfraIfIndex);

    if (aJoin)
    {
        // Suggested workaround for netif not dropping
        // a previous multicast membership.
        setsockopt(mFd6, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, &mreq6, sizeof(mreq6));
    }

    return SetSocketOptionValue(mFd6, IPPROTO_IPV6, aJoin ? IPV6_ADD_MEMBERSHIP : IPV6_DROP_MEMBERSHIP, &mreq6,
                                sizeof(mreq6), "IP6_ADD/DROP_MEMBERSHIP");
}

void MdnsSocket::CloseIp6Socket(void)
{
    if (mFd6 >= 0)
    {
        close(mFd6);
        mFd6 = -1;
    }
}

otError MdnsSocket::SetReuseAddrPortOptions(int aFd)
{
    otError error;

    SuccessOrExit(error = SetSocketOption<int>(aFd, SOL_SOCKET, SO_REUSEADDR, 1, "SO_REUSEADDR"));
    SuccessOrExit(error = SetSocketOption<int>(aFd, SOL_SOCKET, SO_REUSEPORT, 1, "SO_REUSEPORT"));

exit:
    return error;
}

otError MdnsSocket::SetSocketOptionValue(int         aFd,
                                         int         aLevel,
                                         int         aOption,
                                         const void *aValue,
                                         uint32_t    aValueLength,
                                         const char *aOptionName)
{
    otError error = OT_ERROR_NONE;

    if (setsockopt(aFd, aLevel, aOption, aValue, aValueLength) != 0)
    {
        error = OT_ERROR_FAILED;
        LogCrit("Failed to setsockopt(%s) - errno: %s", aOptionName, strerror(errno));
    }

    return error;
}

} // namespace Posix
} // namespace ot

#endif // OPENTHREAD_CONFIG_MULTICAST_DNS_ENABLE
