/*
 *  Copyright (c) 2016, The OpenThread Authors.
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

/**
 * @file
 *   This file implements the local Thread Network Data.
 */

#include "network_data_local.hpp"

#if OPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE || OPENTHREAD_CONFIG_TMF_NETDATA_SERVICE_ENABLE

#include "instance/instance.hpp"

namespace ot {
namespace NetworkData {

RegisterLogModule("NetworkData");

#if OPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE

Error Local::AddOnMeshPrefix(const OnMeshPrefixConfig &aConfig)
{
    Error error = kErrorInvalidArgs;

    VerifyOrExit(aConfig.IsValid(GetInstance()));

    error =
        AddPrefix(aConfig.GetPrefix(), NetworkDataTlv::kTypeBorderRouter, aConfig.ConvertToTlvFlags(), aConfig.mStable);

exit:
    return error;
}

bool Local::ContainsOnMeshPrefix(const Ip6::Prefix &aPrefix) const
{
    const PrefixTlv *tlv;
    bool             contains = false;

    VerifyOrExit((tlv = FindPrefix(aPrefix)) != nullptr);
    VerifyOrExit(tlv->FindSubTlv(NetworkDataTlv::kTypeBorderRouter) != nullptr);

    contains = true;

exit:
    return contains;
}

Error Local::AddHasRoutePrefix(const ExternalRouteConfig &aConfig)
{
    Error error = kErrorInvalidArgs;

    VerifyOrExit(aConfig.IsValid(GetInstance()));

    error = AddPrefix(aConfig.GetPrefix(), NetworkDataTlv::kTypeHasRoute, aConfig.ConvertToTlvFlags(), aConfig.mStable);

exit:
    return error;
}

Error Local::AddPrefix(const Ip6::Prefix &aPrefix, NetworkDataTlv::Type aSubTlvType, uint16_t aFlags, bool aStable)
{
    Error      error = kErrorNone;
    uint8_t    subTlvLength;
    PrefixTlv *prefixTlv;

    IgnoreError(RemovePrefix(aPrefix));

    subTlvLength = (aSubTlvType == NetworkDataTlv::kTypeBorderRouter)
                       ? sizeof(BorderRouterTlv) + sizeof(BorderRouterEntry)
                       : sizeof(HasRouteTlv) + sizeof(HasRouteEntry);

    prefixTlv = As<PrefixTlv>(AppendTlv(sizeof(PrefixTlv) + aPrefix.GetBytesSize() + subTlvLength));
    VerifyOrExit(prefixTlv != nullptr, error = kErrorNoBufs);

    prefixTlv->Init(0, aPrefix);
    prefixTlv->SetSubTlvsLength(subTlvLength);

    if (aSubTlvType == NetworkDataTlv::kTypeBorderRouter)
    {
        BorderRouterTlv *brTlv = As<BorderRouterTlv>(prefixTlv->GetSubTlvs());
        brTlv->Init();
        brTlv->SetLength(brTlv->GetLength() + sizeof(BorderRouterEntry));
        brTlv->GetEntry(0)->Init();
        brTlv->GetEntry(0)->SetFlags(aFlags);
    }
    else // aSubTlvType is NetworkDataTlv::kTypeHasRoute
    {
        HasRouteTlv *hasRouteTlv = As<HasRouteTlv>(prefixTlv->GetSubTlvs());
        hasRouteTlv->Init();
        hasRouteTlv->SetLength(hasRouteTlv->GetLength() + sizeof(HasRouteEntry));
        hasRouteTlv->GetEntry(0)->Init();
        hasRouteTlv->GetEntry(0)->SetFlags(static_cast<uint8_t>(aFlags));
    }

    if (aStable)
    {
        prefixTlv->SetStable();
        prefixTlv->GetSubTlvs()->SetStable();
    }

    DumpDebg("AddPrefix", GetBytes(), GetLength());

exit:
#if OPENTHREAD_CONFIG_BORDER_ROUTER_SIGNAL_NETWORK_DATA_FULL
    if (error == kErrorNoBufs)
    {
        Get<Notifier>().SignalNetworkDataFull();
    }
#endif

    return error;
}

Error Local::RemovePrefix(const Ip6::Prefix &aPrefix)
{
    Error      error = kErrorNone;
    PrefixTlv *tlv;

    VerifyOrExit((tlv = FindPrefix(aPrefix)) != nullptr, error = kErrorNotFound);
    RemoveTlv(tlv);

exit:
    DumpDebg("RmvPrefix", GetBytes(), GetLength());
    return error;
}

void Local::UpdateRloc(PrefixTlv &aPrefixTlv)
{
    uint16_t rloc16 = Get<Mle::Mle>().GetRloc16();

    for (NetworkDataTlv *cur = aPrefixTlv.GetSubTlvs(); cur < aPrefixTlv.GetNext(); cur = cur->GetNext())
    {
        switch (cur->GetType())
        {
        case NetworkDataTlv::kTypeHasRoute:
            As<HasRouteTlv>(cur)->GetEntry(0)->SetRloc(rloc16);
            break;

        case NetworkDataTlv::kTypeBorderRouter:
            As<BorderRouterTlv>(cur)->GetEntry(0)->SetRloc(rloc16);
            break;

        default:
            OT_ASSERT(false);
        }
    }
}

#endif // OPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE

#if OPENTHREAD_CONFIG_TMF_NETDATA_SERVICE_ENABLE
Error Local::AddService(uint32_t           aEnterpriseNumber,
                        const ServiceData &aServiceData,
                        bool               aServerStable,
                        const ServerData  &aServerData)
{
    Error       error = kErrorNone;
    ServiceTlv *serviceTlv;
    ServerTlv  *serverTlv;
    uint16_t    serviceTlvSize = ServiceTlv::CalculateSize(aEnterpriseNumber, aServiceData.GetLength()) +
                              sizeof(ServerTlv) + aServerData.GetLength();

    IgnoreError(RemoveService(aEnterpriseNumber, aServiceData));

    VerifyOrExit(serviceTlvSize <= kMaxSize, error = kErrorNoBufs);

    serviceTlv = As<ServiceTlv>(AppendTlv(serviceTlvSize));
    VerifyOrExit(serviceTlv != nullptr, error = kErrorNoBufs);

    serviceTlv->Init(/* aServiceId */ 0, aEnterpriseNumber, aServiceData);
    serviceTlv->SetSubTlvsLength(sizeof(ServerTlv) + aServerData.GetLength());

    serverTlv = As<ServerTlv>(serviceTlv->GetSubTlvs());
    serverTlv->Init(Get<Mle::Mle>().GetRloc16(), aServerData);

    // According to Thread spec 1.1.1, section 5.18.6 Service TLV:
    // "The Stable flag is set if any of the included sub-TLVs have their Stable flag set."
    // The meaning also seems to be 'if and only if'.
    if (aServerStable)
    {
        serviceTlv->SetStable();
        serverTlv->SetStable();
    }

    DumpDebg("AddService", GetBytes(), GetLength());

exit:
#if OPENTHREAD_CONFIG_BORDER_ROUTER_SIGNAL_NETWORK_DATA_FULL
    if (error == kErrorNoBufs)
    {
        Get<Notifier>().SignalNetworkDataFull();
    }
#endif

    return error;
}

Error Local::RemoveService(uint32_t aEnterpriseNumber, const ServiceData &aServiceData)
{
    Error       error = kErrorNone;
    ServiceTlv *tlv;

    VerifyOrExit((tlv = FindService(aEnterpriseNumber, aServiceData, kServiceExactMatch)) != nullptr,
                 error = kErrorNotFound);
    RemoveTlv(tlv);

exit:
    DumpDebg("RmvService", GetBytes(), GetLength());
    return error;
}

void Local::UpdateRloc(ServiceTlv &aService)
{
    uint16_t rloc16 = Get<Mle::Mle>().GetRloc16();

    for (NetworkDataTlv *cur = aService.GetSubTlvs(); cur < aService.GetNext(); cur = cur->GetNext())
    {
        switch (cur->GetType())
        {
        case NetworkDataTlv::kTypeServer:
            As<ServerTlv>(cur)->SetServer16(rloc16);
            break;

        default:
            OT_ASSERT(false);
        }
    }
}

#endif // OPENTHREAD_CONFIG_TMF_NETDATA_SERVICE_ENABLE

void Local::UpdateRloc(void)
{
    for (NetworkDataTlv *cur = GetTlvsStart(); cur < GetTlvsEnd(); cur = cur->GetNext())
    {
        switch (cur->GetType())
        {
#if OPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE
        case NetworkDataTlv::kTypePrefix:
            UpdateRloc(*As<PrefixTlv>(cur));
            break;
#endif

#if OPENTHREAD_CONFIG_TMF_NETDATA_SERVICE_ENABLE

        case NetworkDataTlv::kTypeService:
            UpdateRloc(*As<ServiceTlv>(cur));
            break;
#endif

        default:
            OT_ASSERT(false);
        }
    }
}

} // namespace NetworkData
} // namespace ot

#endif // OPENTHREAD_CONFIG_BORDER_ROUTER_ENABLE || OPENTHREAD_CONFIG_TMF_NETDATA_SERVICE_ENABLE
