# Module to perform arbitrary WordPress REST API calls.
#
# Usage:
#
#   msf6 > use auxiliary/multi/webapp/wordpress/wordpress_rest_api
#   msf6 > set USERNAME admin
#   msf6 > set PASSWORD password
#   msf6 > set REST_ROUTE /myapi/v1/my_endpoint
#   msf6 > set BODY json-payload (or file:mypayload.json)
#   msf6 > set RHOST example.com
#   msf6 > set SSL true
#   msf6 > set RPORT 443
#   msf6 > run
#
# If USERNAME/PASSWORD is set, the module will automatically try to fetch a REST nonce
# using the `rest-nonce` ajax action, and use this in the actual REST request.
#

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HTTP::Wordpress

  def initialize(info = {})
    @cookies = nil

    super(
      update_info(
        info,
        {
          'Name' => 'WP Generic call REST API',
          'Description' => %q{
            Calls a rest api endpoint in WordPress with an optional json payload.

            The REST_ROUTE is the REST API endpoint to invoke, without the `/wp-json/` or
            `?rest_route=` previxes.

            If USERNAME/PASSWORD is set, the module will automatically try to fetch a REST nonce
            using the `rest-nonce` ajax action, and use this in the actual REST request.

            If BODY is set, the request will be a POST, otherwise a GET.

            If the BODY is specified inline, remember to enclose it in single quotes, or
            escape all the double quotes.
          },
          'Version' => '1',
          'Authors' => [ 'Harald Eilertsen <harald.eilertsen@automattic.com' ],
          'License' => GPL_LICENSE,
          'Platform' => 'php',
          'Arch' => ARCH_PHP,
          'Targets' => [ ['WordPress', {}] ],
          'DefaultTarget' => 0
        }
      )
    )

    register_options( [
      OptString.new( 'USERNAME', 'The admin user we\'ll be exploiting.' ),
      OptString.new( 'PASSWORD', 'Password for the admin user.' ),
      OptString.new( 'REST_ROUTE', 'The REST API endpoint to call', required: true ),
      OptString.new( 'BODY',     'The payload body in json format, load from file with "file:..."' ),
    ])
  end

  def check
    cookie = wordpress_login(username, password)
    if cookie.nil?
      store_valid_credential(user: username, private: password, proof: cookie)
      return CheckCode::Safe
    end

    CheckCode::Appears
  end

  def username
    datastore['USERNAME']
  end

  def password
    datastore['PASSWORD']
  end

  def rest_uri
    normalize_uri(
      target_uri.path,
      "index.php?rest_route=#{Rex::Text.uri_encode(datastore['REST_ROUTE'])}"
    )
  end

  def body
    datastore['BODY']
  end

  def login
    if username
      print_status("Logging in...")
      @cookies = wordpress_login(username, password)

      fail_with( Msf::Module::Failure::NoAccess, "Login failed." ) if @cookies.nil?

      store_valid_credential(user: username, private: password, proof: @cookies)
    end
  end

  def get_rest_nonce
    if @cookies
      print_status("Fetching REST nonce...")

      res = send_request_raw({
        'uri' => wordpress_url_admin_ajax + '?action=rest-nonce',
        'method' => 'GET',
        'cookie' => @cookies
      })

      if res.code != 200
        fail_with( Msf::Module::Failure::Unknown, 'Could not retreive rest nonce.' )
      end

      @rest_nonce = res.body
    end
  end

  def run
    fail_with(Failure::NotFound, 'Not a WordPress site?') unless wordpress_and_online?

    login
    get_rest_nonce

    headers = {
        'Content-Type' => 'application/json',
    }

    headers['X-WP-Nonce'] = @rest_nonce if @rest_nonce

    res = send_request_raw({
      'uri' => rest_uri,
      'method' => body.empty? ? 'GET' : 'POST',
      'headers' => headers,
      'cookie' => @cookies,
      'data' => body
    })

    print_status("Server returned: #{res.code} #{res.message}")
    print_status(res.body)
  end
end
