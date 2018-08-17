#include "process.h"

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

// If enabled, don't direct ovpn3 core logging to
// ClientAPI::OpenVPNClient::log() virtual method.
// Instead, logging will go to LogBaseSimple::log().
// In this case, make sure to define:
//   LogBaseSimple log;
// at the top of your main() function to receive
// log messages from all threads.
// Also, note that the OPENVPN_LOG_GLOBAL setting
// MUST be consistent across all compilation units.
#ifdef OPENVPN_USE_LOG_BASE_SIMPLE
#define OPENVPN_LOG_GLOBAL // use global rather than thread-local log object pointer
#include <openvpn/log/logbasesimple.hpp>
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
#include <openvpn/common/getpw.hpp>
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

#if defined(OPENVPN_PLATFORM_WIN)
#include <openvpn/win/console.hpp>
#endif

using namespace openvpn;


class Client : public ClientAPI::OpenVPNClient {
public:

    //hooks for callbacking go integration bidings
    user_data userData;

    log_callback logCallback;

    stats_callback statsCallback;

    event_callback eventCallback;


private:
    virtual bool socket_protect(int socket) override {
        logCallback(userData, "Socket protect called (Noop)");
        return true;
    }

    virtual void event(const ClientAPI::Event &ev) override {
        conn_event myEvent;

        myEvent.error = ev.error;
        myEvent.fatal = ev.fatal;
        myEvent.name = (char *) ev.name.c_str();
        myEvent.info = (char *) ev.info.c_str();
        eventCallback(userData, myEvent);
    }

    virtual void log(const ClientAPI::LogInfo &log) override {
        logCallback(userData, (char *)log.text.c_str());
    }

    virtual void clock_tick() override {
        conn_stats stats;
        statsCallback(userData, stats);
    }

    virtual void external_pki_cert_request(ClientAPI::ExternalPKICertRequest &certreq) override {
            certreq.error = true;
            certreq.errorText = "external_pki_cert_request not implemented";
    }

    virtual void external_pki_sign_request(ClientAPI::ExternalPKISignRequest &signreq) override {
            signreq.error = true;
            signreq.errorText = "external_pki_sign_request not implemented";
    }

    // RNG callback
    static int rng_callback(void *arg, unsigned char *data, size_t len) {
        Client *self = (Client *) arg;
        if (!self->rng) {
            self->rng.reset(new SSLLib::RandomAPI(false));
            self->rng->assert_crypto();
        }
        return self->rng->rand_bytes_noexcept(data, len) ? 0 : -1; // using -1 as a general-purpose mbed TLS error code
    }

    virtual bool pause_on_connection_timeout() override {
        return false;
    }

    RandomAPI::Ptr rng;      // random data source for epki
};


int
initProcess(const char *profile_content, user_data userData, stats_callback statsCallback, log_callback logCallback, event_callback eventCallback) {

    int ret = 0;

#ifdef OPENVPN_LOG_LOGBASE_H
    LogBaseSimple log;
#endif

    try {
        Client::init_process();

        ClientAPI::Config config;
        config.guiVersion = "cli 1.0";
        config.content = profile_content;

        config.info = true;
        config.clockTickMS = 1000;   //ticks every 1 sec
        config.disableClientCert = true;  //we don't use certs for client identification


        Client client;
        client.userData = userData;
        client.logCallback = logCallback;
        client.statsCallback = statsCallback;
        client.eventCallback = eventCallback;

        const ClientAPI::EvalConfig eval = client.eval_config(config);
        if (eval.error) {
            OPENVPN_THROW_EXCEPTION("eval config error: " << eval.message);
        }

        //TODO username, password?
        ClientAPI::ProvideCreds creds;
        creds.username = "testuser";
        creds.password = "testpassword";
        ClientAPI::Status creds_status = client.provide_creds(creds);
        if (creds_status.error) {
            OPENVPN_THROW_EXCEPTION("creds error: " << creds_status.message);
        }

        ClientAPI::Status connect_status = client.connect();
        if (connect_status.error) {
            OPENVPN_THROW_EXCEPTION("connect error: " << connect_status.message);
        }
        logCallback(userData, "Openvpn client finished");
    }
    catch (const std::exception &e) {
        logCallback(userData, (char *)(e.what()));
        ret = 1;
    }

    Client::uninit_process();

    return ret;
}

void checkLibrary(user_data userData, log_callback logCallback) {
    logCallback(userData, (char *)ClientAPI::OpenVPNClient::platform().c_str());
    logCallback(userData, (char *)ClientAPI::OpenVPNClient::copyright().c_str());
    logCallback(userData, (char *)ClientAPI::OpenVPNClient::crypto_self_test().c_str());
}