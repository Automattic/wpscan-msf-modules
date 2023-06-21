# A Metasploit helper module to verify most typical proof-of-concepts for
# vulnerabilities reported to WPScan.
#
# Usage:
#
#   msf6 > use auxiliary/multi/webapp/wordpress/wp_check_poc
#   msf6 > set USERNAME admin
#   msf6 > set PASSWORD password
#   msf6 > set URI /wp-admin/admin.php?page=vulneable
#   msf6 > set NONCE_REGEX 'wp_nonce="([0-9a-f]+)'
#   msf6 > set POC success
#   msf6 > set BODY urlencoded params
#   msf6 > set RHOST example.com
#   msf6 > set SSL true
#   msf6 > set RPORT 443
#   msf6 > run
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
          'Name' => 'WP Check Proof-of-Concept',
          'Description' => %q{
            Helper module to simplify checking and reporting most typical Proof-of-Concepts
            for WordPress plugin/theme vulnerabilities reported to WPScan.

            If USERNAME and PASSWORD is set, the given credentials will be used to log in
            to the target site before running the proof-of-concept.

            If NONCE_URI and NONCE_REGEX is set, these will be used to extract a nonce from
            the given NONCE_URI. If only the NONCE_REGEX is set, the URI will be used to
            fetch the nonce too.

            The Nonce can be passed to the PoC request using the '{{NONCE}}' placholder in
            the body or query parameters.

            If BODY is set, the request will be a POST, otherwise a GET.

            If POC is set, it will be matched against the response to the request sent to URI,
            to validate the Proof-of-Concept. Otherwise the response body and status code is
            output to the console.
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
      OptString.new( 'USERNAME',    'The admin user we\'ll be exploiting.' ),
      OptString.new( 'PASSWORD',    'Password for the admin user.' ),
      OptString.new( 'URI',         'The uri (path) to invoke', required: true ),
      OptString.new( 'BODY',        'The message body for POST requests' ),
      OptString.new( 'NONCE_URI',   'The uri where to fetch a nonce if needed.' ),
      OptRegexp.new( 'NONCE_REGEX', 'The regex for capturing the nonce if needed.' ),
      OptRegexp.new( 'POC',         'A regex for validating the proof of concept.' ),
    ])
  end

  def username
    datastore['USERNAME']
  end

  def password
    datastore['PASSWORD']
  end

  def uri
    datastore['URI']
  end

  def body
    datastore['BODY']
  end

  def nonce_uri
    datastore['NONCE_URI']
  end

  def nonce_regex
    datastore['NONCE_REGEX']
  end

  def login
    if username
      print_status("Logging in...")
      @cookies = wordpress_login(username, password)

      fail_with( Msf::Module::Failure::NoAccess, "Login failed." ) if @cookies.nil?

      store_valid_credential(user: username, private: password, proof: @cookies)
    end
  end

  def fetch_nonce
    if nonce_uri && nonce_regex
      res = send_request_cgi({
        'uri' => nonce_uri,
        'method' => 'GET',
        'cookie' => @cookies,
      })

      @nonce = nonce_regex.match(res.body)[1]
    end
  end

  def verify_poc(response)
    if datastore['POC']
      r = datastore['POC']
      if r =~ response.to_terminal_output
        print_status("POC Successful! (#{$~})")
      else
        print_status("POC Failed!")
      end
    else
      print_status(response.body)
    end
  end

  def run
    fail_with(Failure::NotFound, 'Not a WordPress site?') unless wordpress_and_online?

    login
    fetch_nonce

    res = send_request_cgi({
      'uri' => uri,
      'method' => (body.nil? || body.empty?) ? 'GET' : 'POST',
      'cookie' => @cookies,
      'data' => body
    })

    print_status("Server returned: #{res.code} #{res.message}")
    verify_poc(res)
  end
end
