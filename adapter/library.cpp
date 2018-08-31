#include "library.h"
#include "tunsetup.h"

#include "tunsetup_impl.hpp"

class Client : public TunBuilderDelegate {
public:

    Client(const callbacks_delegate &callbacks, const tun_builder_callbacks &builder_callbacks) : TunBuilderDelegate(builder_callbacks) {
        this->callbacks = callbacks;
    }

    virtual ~Client() {

    }

    void LogMessage(const char * msg) {
        callbacks.logCallback(callbacks.usrData, (char *)msg);
    }
private:

    callbacks_delegate callbacks;

    virtual bool socket_protect(int socket) override {
        LogMessage("Socket protect called (Noop)");
        return true;
    }

    virtual void event(const ClientAPI::Event &ev) override {
        conn_event myEvent;

        myEvent.error = ev.error;
        myEvent.fatal = ev.fatal;
        myEvent.name = (char *) ev.name.c_str();
        myEvent.info = (char *) ev.info.c_str();
        callbacks.eventCallback(callbacks.usrData, myEvent);
    }

    virtual void log(const ClientAPI::LogInfo &log) override {
        callbacks.logCallback(callbacks.usrData, (char *)log.text.c_str());
    }

    virtual void clock_tick() override {
        ClientAPI::TransportStats trStats = transport_stats();
        conn_stats stats;
        stats.bytes_in = trStats.bytesIn;
        stats.bytes_out = trStats.bytesOut;
        callbacks.statsCallback(callbacks.usrData, stats);
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



void * new_session(const char *profile_content, user_credentials credentials , callbacks_delegate callbacks, tun_builder_callbacks builder_callbacks) {

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


        clientPtr = new Client(callbacks, builder_callbacks);

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
        callbacks.logCallback(callbacks.usrData, (char *)(e.what()));
        //TODO auto pointer ?
        if(clientPtr != NULL) {
            delete clientPtr;
            clientPtr = NULL;
        }
        Client::uninit_process();
    }


    return clientPtr;
}

int start_session(void *ptr) {
    Client *client = (Client *)(ptr);
    ClientAPI::Status connect_status = client->connect();
    if (connect_status.error) {
        client->LogMessage(connect_status.message.c_str());
        return 1;
    }
    client->LogMessage("Openvpn3 session ended");
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

void check_library(user_callback_data userData, log_callback logCallback) {
    logCallback(userData, (char *)ClientAPI::OpenVPNClient::platform().c_str());
    logCallback(userData, (char *)ClientAPI::OpenVPNClient::copyright().c_str());
}