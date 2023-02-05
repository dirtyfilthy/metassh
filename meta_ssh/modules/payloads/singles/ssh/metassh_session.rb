##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'msf/core/handler/meta_ssh'
require 'msf/base/sessions/meta_ssh'


module MetasploitModule
  include Msf::Payload::Single

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'MetaSsh Session',
      'Description'    => 'Spawn a MetaSsh session',
      'PayloadType'    => 'ssh',
      'ConnectionType' => 'tunnel',
      'Author'         => [
        'alhazred',
        'rageltman <rageltman [at] sempervictus>'
      ],
      # 'Platform'       => 'ssh',
      'Platform'   => %w[linux osx unix python bsd],
      'Arch'           => ARCH_SSH,
      'License'        => MSF_LICENSE,
      'Handler'        => Msf::Handler::MetaSsh,
      'Payload'        => {
        'Offsets'  => { },
        'Payload'  => ''
      },
      'Session'    => Msf::Sessions::MetaSsh))
  end

end

