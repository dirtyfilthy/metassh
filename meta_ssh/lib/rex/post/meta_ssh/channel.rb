#!/usr/bin/env ruby


module Rex
module Post
module MetaSSH
class Channel


	##
	#
	# Constructor
	#
	##

	#
	# Initializes the instance's attributes, such as client context,
	# class identifier, type, and flags.
	#



	attr_accessor :channel, :thread, :error, :ssh, :on_exit_signal, :on_exit_status, :type, :info
	attr_accessor :lsock, :rsock, :cid, :client, :monitor

	module PeerInfo
		include ::Rex::IO::Stream
		attr_accessor :peerinfo
		attr_accessor :localinfo
	end

	def initialize(client, cleanup = false, &block)

		self.lsock, self.rsock = Rex::Socket.tcp_socket_pair()
		self.lsock.extend(Rex::IO::Stream)
		self.lsock.extend(PeerInfo)
		self.rsock.extend(Rex::IO::Stream)
		self.type=""
    self.info=""
    self.client=client
    self.client.add_channel(self)
    self.thread = Thread.new(client.ssh, cleanup) do |rssh,rcleanup|

			begin
				info = rssh.transport.socket.getpeername
				self.lsock.peerinfo  = "#{info[1]}:#{info[2]}"

				info = rssh.transport.socket.getsockname
				self.lsock.localinfo = "#{info[1]}:#{info[2]}"

				rssh.open_channel do |c|


					c.on_eof do
							self.close
						end

						c.on_close do
						  self.close
            end

						c.on_data do |ch,data|
							self.rsock.write(data)
						end

						c.on_extended_data do |ch, ctype, data|
							self.rsock.write(data)
						end

            c.on_request "exit-status" do |ch,data|
              if self.on_exit_status.is_a? Proc
                self.on_exit_status.call(self,data.read_long)
              else
                self.close
              end
            end  



            c.on_request "exit-signal" do |ch,data|
              if self.on_exit_signal.is_a? Proc
                self.on_exit_status.call(self, data.read_string)
              else
                self.close
              end
            end  

						self.channel = c
            yield self
					end

				self.monitor = Thread.new do
					while(true)
						next if not self.rsock.has_read_data?(1.0)
						buff = self.rsock.read(16384)
						break if not buff
						verify_channel
						self.channel.send_data(buff) if buff
					end
				end



			rescue ::Exception => e
				self.error = e
        self.close
				#::Kernel.warn "BOO: #{e.inspect}"
				#::Kernel.warn e.backtrace.join("\n")
			ensure
			end

		end
	end

  def write(buf, length=nil)
		if ((length != nil) &&
		    (buf.length >= length))
			buf = buf[0..length]
		else
			length = buf.length
		end
    lsock.write(buf)
  end


  def exec(*args)
    channel.exec(*args)
  end

  def close
    begin
      self.client.remove_channel(self)
      self.monitor.kill if self.monitor
      self.thread.kill if self.thread
      self.channel.close
      self.lsock.close
    rescue Exception => e
      puts e
    end
  end



	#
	# Prevent a race condition
	#
	def verify_channel
		while ! self.channel
			raise EOFError if ! self.thread.alive?
			::IO.select(nil, nil, nil, 0.10)
		end
	end


	##
	#
	# Channel interaction
	#
	##
	def cleanup
	end

end

end; end; end

