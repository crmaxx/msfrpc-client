require 'msgpack'
require 'rex'
require 'rex/proto/http'
require 'msfrpc_client/constants'

module Msf
  module RPC
    class Client
      attr_accessor :username, :password, :token, :client

      ALLOWED_CODE = [200, 401, 403, 500]

      def initialize(config = {})
        @username = config[:username]
        @password = config[:password]
        @token = config[:token]

        host = config.fetch(:host) { '127.0.0.1' }
        port = config.fetch(:port) { 55_553 }
        ssl = config.fetch(:ssl) { false }
        ssl_version = config.fetch(:ssl) { 'TLS1' }
        context = config.fetch(:context, {})

        @uri = config.fetch(:uri) { "/api/#{Msf::RPC::API_VERSION}" }

        @client = Rex::Proto::Http::Client.new(host, port, context, ssl, ssl_version)
        @client.set_config(
          vhost: host,
          agent: "Metasploit Pro RPC Client/#{API_VERSION}",
          read_max_data: (1024 * 1024 * 512)
        )

        login(@username, @password) if @token.blank? || @username || @password
      end

      def login(user, pass)
        response = execute("auth.login", user: user, password: pass)
        fail "authentication failed" unless response || response['result'] == "success"
        @token = response['token']
        true
      end

      def call(method, opts = {})
        fail "client not authenticated" if @token.blank? && method != "auth.login"
        execute(method, opts)
      end

      private

      def execute(method, opts = {})
        data = client_data(method, opts)
        request = client_request(data)
        response = @client.send_recv(request)

        if response && ALLOWED_CODE.include?(response.code)
          unpacked_response = MessagePack.unpack(response.body)

          if unpacked_response && unpacked_response.is_a?(::Hash) && unpacked_response['error'] == true
            fail Msf::RPC::ServerException.new(response.code,
                                               unpacked_response['error_message'] || unpacked_response['error_string'],
                                               unpacked_response['error_class'],
                                               unpacked_response['error_backtrace'])
          end

          unpacked_response
        else
          fail response.inspect
        end
      end

      def client_data(method, opts = {})
        [method, opts.values].flatten.to_msgpack
      end

      def client_request(data)
        @client.request_cgi('method' => 'POST',
                            'uri'    => @uri,
                            'ctype'  => 'binary/message-pack',
                            'data'   => data)
      end
    end
  end
end
