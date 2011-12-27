#
# $Id$
# $Revision$
#

# top level constant ?! 

ARCH_SSH = "ssh"

module Msf

###
#
# MetaSSH by alhazred
#
###

class Plugin::MetaSSH < Msf::Plugin

  attr_accessor :framework

  def initialize(framework, opts={})

  # register our new arch type

  ::ARCH_TYPES << ::ARCH_SSH unless ::ARCH_TYPES.include?(::ARCH_SSH)

  # add meta_ssh lib to the path
  
  $:.unshift(File.join(File.dirname(__FILE__),"meta_ssh","lib"))

  # load our modules
  
  framework.modules.add_module_path(File.join(File.dirname(__FILE__),"meta_ssh","modules"))
  end

  def name
    "metaSSH"
  end

end

end
