require 'msf/core/post/file'

module Msf
module Scripts
module MetaSSH
module Common

  include ::Msf::Post::File

	def write_file(file_name, data)
		fd = session.fs.file.new(file_name, "wb")
		fd.write(data)
		fd.close
		return true
	end
	
  def append_file(file_name, data)
		fd = session.fs.file.new(file_name, "wab")
		fd.write(data)
		fd.close
		return true
	end

	def read_file(file_name)
		fd = session.fs.file.new(file_name, "rb")
		data = ''
		begin
			until fd.eof?
				data << fd.read
			end
		ensure
			fd.close
		end
		data
	end


end
end
end
end

