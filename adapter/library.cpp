#include "library.h"

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
        ClientAPI::TransportStats trStats = transport_stats();
        conn_stats stats;
        stats.bytes_in = trStats.bytesIn;
        stats.bytes_out = trStats.bytesOut;
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



void * new_session(const char *profile_content, user_credentials credentials , user_data userData, stats_callback statsCallback, log_callback logCallback, event_callback eventCallback) {

    Client * clientPtr = NULL;

    try {
        Client::init_process();

        ClientAPI::Config config;
        config.guiVersion = "cli 1.0";
        config.content = profile_content;

        config.info = true;
        config.clockTickMS = 1000;   //ticks every 1 sec
        config.disableClientCert = true;  //we don't use certs for client identification
        config.connTimeout = 10; // connection timeout - 10 seconds (make it configurable?)
        config.tunPersist = true;
        config.compressionMode = "yes";


        clientPtr = new Client();
        clientPtr->userData = userData;
        clientPtr->logCallback = logCallback;
        clientPtr->statsCallback = statsCallback;
        clientPtr->eventCallback = eventCallback;

        const ClientAPI::EvalConfig eval = clientPtr->eval_config(config);
        if (eval.error) {
            OPENVPN_THROW_EXCEPTION("eval config error: " << eval.message);
        }


        ClientAPI::ProvideCreds creds;
        creds.username = credentials.username;
        creds.password = credentials.password;
        ClientAPI::Status creds_status = clientPtr->provide_creds(creds);
        if (creds_status.error) {
            OPENVPN_THROW_EXCEPTION("creds error: " << creds_status.message);
        }

    }
    catch (const std::exception &e) {
        logCallback(userData, (char *)(e.what()));
        if(clientPtr != NULL) {
            delete clientPtr;
            clientPtr = NULL;
        }
    }


    return clientPtr;
}

int start_session(void *ptr) {
    Client *client = (Client *)(ptr);
    ClientAPI::Status connect_status = client->connect();
    if (connect_status.error) {
        client->logCallback(client->userData, (char *)connect_status.message.c_str());
        return 1;
    }
    client->logCallback(client->userData, "Openvpn3 session ended");
    return 0;
}

void stop_session(void *ptr) {
    Client *client = (Client *)(ptr);
    client->stop();
}

void cleanup_session(void *ptr) {
    Client *client = (Client *)(ptr);
    delete client;
    Client::uninit_process();
}

void check_library(user_data userData, log_callback logCallback) {
    logCallback(userData, (char *)ClientAPI::OpenVPNClient::platform().c_str());
    logCallback(userData, (char *)ClientAPI::OpenVPNClient::copyright().c_str());
}