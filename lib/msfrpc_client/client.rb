require 'msgpack'
require 'rex'
require 'rex/proto/http'
require 'msfrpc_client/constants'

module Msf
  module RPC
    class Client
      attr_accessor :token, :info

      def initialize(config = {})
        self.info = {
          host: '127.0.0.1',
          port: 55_553,
          uri:  "/api/#{Msf::RPC::API_VERSION}",
          ssl:  false,
          ssl_version: 'TLS1',
          context: {}
        }.merge(config)

        self.token = info[:token]

        login(info[:user], info[:pass]) unless token || info[:user] || info[:pass]
      end

      def login(user, pass)
        res = call("auth.login", user, pass)
        fail "authentication failed" unless res || res['result'] == "success"
        self.token = res['token']
        true
      end

      def call(meth, *args)
        if meth != "auth.login"
          fail "client not authenticated" unless token
          args.unshift(token)
        end

        args.unshift(meth)

        unless @cli
          @cli = Rex::Proto::Http::Client.new(info[:host], info[:port], info[:context], info[:ssl], info[:ssl_version])
          @cli.set_config(
            vhost: info[:host],
            agent: "Metasploit Pro RPC Client/#{API_VERSION}",
            read_max_data: (1024 * 1024 * 512)
          )
        end

        req = @cli.request_cgi(
          'method' => 'POST',
          'uri'    => info[:uri],
          'ctype'  => 'binary/message-pack',
          'data'   => args.to_msgpack
        )

        res = @cli.send_recv(req)

        if res && [200, 401, 403, 500].include?(res.code)
          resp = MessagePack.unpack(res.body)

          if resp && resp.is_a?(::Hash) && resp['error'] == true
            fail Msf::RPC::ServerException.new(res.code,
                                               resp['error_message'] || resp['error_string'],
                                               resp['error_class'],
                                               resp['error_backtrace'])
          end

          return resp
        else
          fail res.inspect
        end
      end
    end
  end
end
