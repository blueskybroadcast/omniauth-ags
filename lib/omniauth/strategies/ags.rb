require 'omniauth-oauth2'
require 'rest_client'

module OmniAuth
  module Strategies
    class Ags < OmniAuth::Strategies::OAuth2
      option :name, 'ags'

      option :client_options, {
        site: 'https://www.americangemsociety.org',
        user_info_url: '/ags_ws.php',
        authorize_url: '/member-login?src=pathlms',
        username: 'MUST BE SET',
        password: 'MUST BE SET',
        authentication_action: 'GetMemberInfo',
        authentication_code: 'D2E8B40B-D2B3-C54D-8C90-C93C6C62E32A'
      }

      uid { raw_info[:id] }

      info do
        {
          first_name: raw_info[:first_name],
          last_name: raw_info[:last_name],
          email: raw_info[:email],
          member_id: uid,
          membership_status: raw_info[:membership_status]
        }
      end

      extra do
        { :raw_info => raw_info }
      end

      def request_phase
        slug = session['omniauth.params']['origin'].gsub(/\//,"")
        redirect authorize_url + "&redirectURL=" + callback_url + "?slug=#{slug}"
      end

      def callback_phase
        self.access_token = {
          :token =>  request.params['Token'],
          :token_expires => 60
        }
        self.env['omniauth.auth'] = auth_hash
        call_app!
      end

      def creds
        self.access_token
      end

      def auth_hash
        hash = AuthHash.new(:provider => name, :uid => uid)
        hash.info = info
        hash.credentials = creds
        hash.extra = extra
        hash
      end

      def raw_info
        @raw_info ||= get_user_info
      end

      def get_user_info
        response = RestClient.post(user_info_url,
          {
            "Token" => access_token[:token],
            "AuthorizationCode" => authentication_code,
            "Action" => authentication_action
          }
        )

        parsed_response = JSON.parse(response)

        if parsed_response['message'] == 'Success'
          info = {
            id: parsed_response['data']['MemberID'],
            first_name: parsed_response['data']['FirstName'],
            last_name: parsed_response['data']['LastName'],
            email: parsed_response['data']['Email'],
            membership_status: parsed_response['data']['MembershipStatus']
          }
        else
          nil
        end
      end

      private

      def authentication_action
        options.client_options.authentication_action
      end

      def authentication_code
        options.client_options.authentication_code
      end

      def authorize_url
        "#{options.client_options.site}#{options.client_options.authorize_url}"
      end

      def user_info_url
        "#{options.client_options.site}#{options.client_options.user_info_url}"
      end
    end
  end
end
