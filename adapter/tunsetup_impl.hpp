#ifndef CORE_TUNSETUP_IMPL_H
#define CORE_TUNSETUP_IMPL_H

#include "tunsetup.h"
//this source file was made as header file intentionaly - to keep single source file as compilation target (whole openvpn3 lib uses this style)
#include <string>
#include <iostream>
#include <thread>
#include <memory>
#include <mutex>

#include <openvpn/common/platform.hpp>

#ifdef OPENVPN_PLATFORM_MAC
#include <CoreFoundation/CFBundle.h>
#include <ApplicationServices/ApplicationServices.h>
#endif

// don't export core symbols
#define OPENVPN_CORE_API_VISIBILITY_HIDDEN

// should be included before other openvpn includes,
// with the exception of openvpn/log includes
#include <client/ovpncli.cpp>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/common/signal.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/common/getopt.hpp>
#include <openvpn/common/cleanup.hpp>
#include <openvpn/time/timestr.hpp>
#include <openvpn/ssl/peerinfo.hpp>
#include <openvpn/ssl/sslchoose.hpp>

#ifdef OPENVPN_REMOTE_OVERRIDE
#include <openvpn/common/process.hpp>
#endif

#if defined(USE_MBEDTLS)
#include <openvpn/mbedtls/util/pkcs1.hpp>
#endif

using namespace openvpn;

//TODO this can extetend not OpenVPNClient directly but Just TunBuilderBase and then our client just assembles both? (inherits)
class TunBuilderDelegate: public ClientAPI::OpenVPNClient {
private :
    tun_builder_callbacks callbacks;

public :
    TunBuilderDelegate(const tun_builder_callbacks callbacks) {
        this->callbacks = callbacks;
    }
    virtual ~TunBuilderDelegate() {}
    //delegate all methods from struct to OpenVPNClient

    virtual bool tun_builder_new() override
    {
        return callbacks.new_builder(callbacks.usrData);
    }

    // Optional callback that indicates OSI layer, should be 2 or 3.
    // Defaults to 3.
    virtual bool tun_builder_set_layer(int layer) override
    {
        return callbacks.set_layer(callbacks.usrData, layer);
    }

    // Callback to set address of remote server
    // Never called more than once per tun_builder session.
    virtual bool tun_builder_set_remote_address(const std::string& address, bool ipv6) override
    {
        return callbacks.set_remote_address(callbacks.usrData, (char *)address.c_str(), ipv6 );
    }

    // Callback to add network address to VPN interface
    // May be called more than once per tun_builder session
    virtual bool tun_builder_add_address(const std::string& address,
                                         int prefix_length,
                                         const std::string& gateway, // optional
                                         bool ipv6,
                                         bool net30) override
    {
        return callbacks.add_address(callbacks.usrData, (char *)address.c_str(), prefix_length, (char *)gateway.c_str(), ipv6, net30);
    }

    // Optional callback to set default value for route metric.
    // Guaranteed to be called before other methods that deal
    // with routes such as tun_builder_add_route and
    // tun_builder_reroute_gw.  Route metric is ignored
    // if < 0.
    virtual bool tun_builder_set_route_metric_default(int metric) override
    {
        return callbacks.set_route_metric_default(callbacks.usrData, metric);
    }

    // Callback to reroute default gateway to VPN interface.
    // ipv4 is true if the default route to be added should be IPv4.
    // ipv6 is true if the default route to be added should be IPv6.
    // flags are defined in RGWFlags (rgwflags.hpp).
    // Never called more than once per tun_builder session.
    virtual bool tun_builder_reroute_gw(bool ipv4,
                                        bool ipv6,
                                        unsigned int flags) override
    {
        return callbacks.reroute_gw(callbacks.usrData, ipv4,ipv6, flags);
    }

    // Callback to add route to VPN interface
    // May be called more than once per tun_builder session
    // metric is optional and should be ignored if < 0
    virtual bool tun_builder_add_route(const std::string& address,
                                       int prefix_length,
                                       int metric,
                                       bool ipv6) override
    {
        return callbacks.add_route(callbacks.usrData, (char *)address.c_str(), prefix_length, metric, ipv6);
    }

    // Callback to exclude route from VPN interface
    // May be called more than once per tun_builder session
    // metric is optional and should be ignored if < 0
    virtual bool tun_builder_exclude_route(const std::string& address,
                                           int prefix_length,
                                           int metric,
                                           bool ipv6) override
    {
        return callbacks.exclude_route(callbacks.usrData, (char *)address.c_str(), prefix_length, metric, ipv6);
    }

    // Callback to add DNS server to VPN interface
    // May be called more than once per tun_builder session
    // If reroute_dns is true, all DNS traffic should be routed over the
    // tunnel, while if false, only DNS traffic that matches an added search
    // domain should be routed.
    // Guaranteed to be called after tun_builder_reroute_gw.
    virtual bool tun_builder_add_dns_server(const std::string& address, bool ipv6) override
    {
        return callbacks.add_dns_server(callbacks.usrData, (char *)address.c_str(), ipv6);
    }

    // Callback to add search domain to DNS resolver
    // May be called more than once per tun_builder session
    // See tun_builder_add_dns_server above for description of
    // reroute_dns parameter.
    // Guaranteed to be called after tun_builder_reroute_gw.
    virtual bool tun_builder_add_search_domain(const std::string& domain) override
    {
        return callbacks.add_search_domain(callbacks.usrData, (char *)domain.c_str());
    }

    // Callback to set MTU of the VPN interface
    // Never called more than once per tun_builder session.
    virtual bool tun_builder_set_mtu(int mtu) override
    {
        return callbacks.set_mtu(callbacks.usrData, mtu);
    }

    // Callback to set the session name
    // Never called more than once per tun_builder session.
    virtual bool tun_builder_set_session_name(const std::string& name) override
    {
        return callbacks.set_session_name(callbacks.usrData, (char *)name.c_str());
    }

    // Callback to add a host which should bypass the proxy
    // May be called more than once per tun_builder session
    virtual bool tun_builder_add_proxy_bypass(const std::string& bypass_host) override
    {
        return callbacks.add_proxy_bypass(callbacks.usrData, (char *)bypass_host.c_str());
    }

    // Callback to set the proxy "Auto Config URL"
    // Never called more than once per tun_builder session.
    virtual bool tun_builder_set_proxy_auto_config_url(const std::string& url) override
    {
        return callbacks.set_proxy_auto_config_url(callbacks.usrData, (char *)url.c_str());
    }

    // Callback to set the HTTP proxy
    // Never called more than once per tun_builder session.
    virtual bool tun_builder_set_proxy_http(const std::string& host, int port) override
    {
        return callbacks.set_proxy_http(callbacks.usrData, (char *)host.c_str(), port);
    }

    // Callback to set the HTTPS proxy
    // Never called more than once per tun_builder session.
    virtual bool tun_builder_set_proxy_https(const std::string& host, int port) override
    {
        return callbacks.set_proxy_https(callbacks.usrData, (char *)host.c_str(), port);
    }

    // Callback to add Windows WINS server to VPN interface.
    // WINS server addresses are always IPv4.
    // May be called more than once per tun_builder session.
    // Guaranteed to be called after tun_builder_reroute_gw.
    virtual bool tun_builder_add_wins_server(const std::string& address) override
    {
        return callbacks.add_wins_server(callbacks.usrData, (char *)address.c_str());
    }

    // Optional callback that indicates whether IPv6 traffic should be
    // blocked, to prevent unencrypted IPv6 packet leakage when the
    // tunnel is IPv4-only, but the local machine has IPv6 connectivity
    // to the internet.  Enabled by "block-ipv6" config var.
    virtual bool tun_builder_set_block_ipv6(bool block_ipv6) override
    {
        return callbacks.set_block_ipv6(callbacks.usrData, block_ipv6);
    }

    // Optional callback to set a DNS suffix on tun/tap adapter.
    // Currently only implemented on Windows, where it will
    // set the "Connection-specific DNS Suffix" property on
    // the TAP driver.
    virtual bool tun_builder_set_adapter_domain_suffix(const std::string& name) override
    {
        return callbacks.set_adapter_domain_suffix(callbacks.usrData, (char *)name.c_str());
    }

    // Callback to establish the VPN tunnel, returning a file descriptor
    // to the tunnel, which the caller will henceforth own.  Returns -1
    // if the tunnel could not be established.
    // Always called last after tun_builder session has been configured.
    virtual int tun_builder_establish() override
    {
        return callbacks.establish(callbacks.usrData);
    }

    // Return true if tun interface may be persisted, i.e. rolled
    // into a new session with properties untouched.  This method
    // is only called after all other tests of persistence
    // allowability succeed, therefore it can veto persistence.
    // If persistence is ultimately enabled,
    // tun_builder_establish_lite() will be called.  Otherwise,
    // tun_builder_establish() will be called.
    virtual bool tun_builder_persist() override
    {
        return callbacks.persist(callbacks.usrData);
    }

    // Indicates a reconnection with persisted tun state.
    virtual void tun_builder_establish_lite() override
    {
        callbacks.establish_lite(callbacks.usrData);
    }

    // Indicates that tunnel is being torn down.
    // If disconnect == true, then the teardown is occurring
    // prior to final disconnect.
    virtual void tun_builder_teardown(bool disconnect) override
    {
        callbacks.teardown(callbacks.usrData, disconnect);
    }

};

#endif //CORE_TUNSETUP_IMPL_H
