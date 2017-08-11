require 'omniauth-oauth2'
require 'rest_client'

module OmniAuth
  module Strategies
    class Ags < OmniAuth::Strategies::OAuth2
      option :name, 'ags'

      option :app_options, { app_event_id: nil }

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
        @app_event = prepare_app_event

        self.access_token = {
          :token =>  request.params['Token'],
          :token_expires => 60
        }
        self.env['omniauth.auth'] = auth_hash
        self.env['omniauth.app_event_id'] = @app_event.id
        finalize_app_event
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
        request_log = "#{provider_name} Authentication Request:\nPOST #{user_info_url}, params: { token: #{Provider::SECURITY_MASK} }"
        @app_event.logs.create(level: 'info', text: request_log)
        response = RestClient.post(user_info_url,
          {
            "Token" => access_token[:token],
            "AuthorizationCode" => authentication_code,
            "Action" => authentication_action
          }.to_json, :content_type => :json, :accept => :json
        )

        parsed_response = JSON.parse(response)

        response_log = "#{provider_name} Authentication Response (code: #{response&.code}):\n#{response}"

        if response.code == 200
          @app_event.logs.create(level: 'info', text: response_log)
          {
            id: parsed_response['MemberID'],
            first_name: parsed_response['FirstName'],
            last_name: parsed_response['LastName'],
            email: parsed_response['Email'],
            membership_status: parsed_response['MembershipStatus']
          }
        else
          @app_event.logs.create(level: 'error', text: response_log)
          @app_event.fail!
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

      def finalize_app_event
        app_event_data = {
          user_info: {
            uid: info[:member_id],
            first_name: info[:first_name],
            last_name: info[:last_name],
            email: info[:email],
            membership_status: info[:membership_status]
          }
        }

        @app_event.update(raw_data: app_event_data)
      end

      def prepare_app_event
        slug = request.params['slug']
        account = Account.find_by(slug: slug)
        account.app_events.where(id: options.app_options.app_event_id).first_or_create(activity_type: 'sso')
      end

      def provider_name
        options.name
      end

      def user_info_url
        "#{options.client_options.site}#{options.client_options.user_info_url}"
      end
    end
  end
end
