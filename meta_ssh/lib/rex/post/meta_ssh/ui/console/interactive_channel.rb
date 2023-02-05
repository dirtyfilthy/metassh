module Rex
module Post
module MetaSsh
module Ui

###
#
# Mixin that is meant to extend the base channel class from ssh in a
# manner that adds interactive capabilities.
#
###
module Console::InteractiveChannel

  include Rex::Ui::Interactive

  #
  # Interacts with self.
  #
  def _interact
    # If the channel has a left-side socket, then we can interact with it.
    if (self.lsock)
   self.interacting=true
      interact_stream(self)

    else
      print_error("Channel #{self.cid} does not support interaction.")

    end
  end

  #
  # Called when an interrupt is sent.
  #
  def _interrupt
    prompt_yesno("Terminate channel #{self.cid}?")  
  end

  #
  # Suspends interaction with the channel.
  #
  def _suspend
    # Ask the user if they would like to background the session
    if (prompt_yesno("Background channel #{self.cid}?") == true)

      self.interacting = false
    end
  end

  #
  # Closes the channel like it aint no thang.
  #
  def _interact_complete
    begin
   self.interacting=false
      self.close
    rescue IOError
    end
  end

  #
  # Reads data from local input and writes it remotely.
  #
  def _stream_read_local_write_remote(channel)
    data = user_input.gets
    return if not data

    self.on_command_proc.call(data.strip) if self.on_command_proc
    self.write(data)
  end

  #
  # Reads from the channel and writes locally.
  #
  def _stream_read_remote_write_local(channel)
    data = self.lsock.sysread(16384)

    self.on_print_proc.call(data.strip) if self.on_print_proc
    user_output.print(data)
  end

  #
  # Returns the remote file descriptor to select on
  #
  def _remote_fd(stream)
    self.lsock
  end

end

end
end
end
end
