
module Rex
module Script
class MetaSsh < Base

begin
  require 'msf/scripts/meta_ssh'
  include Msf::Scripts::MetaSsh::Common
rescue ::LoadError
end

end
end
end

