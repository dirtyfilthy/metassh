require 'tempfile'
require 'rex/post/meta_ssh'

module Rex
module Post
module MetaSsh
module Ui

###
#
# The file system portion of the standard API extension.
#
###
class Console::CommandDispatcher::Stdapi::Fs

  Klass = Console::CommandDispatcher::Stdapi::Fs

  include Console::CommandDispatcher

  #
  # Options for the download command.
  #
  @@download_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner." ],
    "-r" => [ false, "Download recursively." ])
  #
  # Options for the upload command.
  #
  @@upload_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner." ],
    "-r" => [ false, "Upload recursively." ])

  #
  # List of supported commands.
  #
  def commands
    {
      "cat"   => "Read the contents of a file to the screen",
      "cd"    => "Change directory",
      "download" => "Download a file or directory",
      "edit"  => "Edit a file",
      "getwd" => "Print working directory",
      "ls"    => "List files",
      "mkdir" => "Make directory",
      "pwd"   => "Print working directory",
      "rmdir" => "Remove directory",
      "upload"   => "Upload a file or directory",
      "lcd"   => "Change local working directory",
      "getlwd"   => "Print local working directory",
      "lpwd"  => "Print local working directory",
      "rm"    => "Delete the specified file",
      "del"   => "Delete the specified file",
      "search"   => "Search for files"
    }
  end

  #
  # Name for this dispatcher.
  #
  def name
    "Stdapi: File system"
  end

  #
  # Search for files.
  #
  def cmd_search( *args )
  
    root = nil
    glob = nil
    recurse = true
    
    opts = Rex::Parser::Arguments.new(
      "-h" => [ false, "Help Banner." ],
      "-d" => [ true,  "The directory/drive to begin searching from. Leave empty to search all drives. (Default: #{root})" ],
      "-f" => [ true,  "The file pattern glob to search for. (e.g. *secret*.doc?)" ],
      "-r" => [ true,  "Recursivly search sub directories. (Default: #{recurse})" ]
    )
    
    opts.parse(args) { | opt, idx, val |
      case opt
        when "-h"
          print_line( "Usage: search [-d dir] [-r recurse] -f pattern" )
          print_line( "Search for files." )
          print_line( opts.usage )
          return
        when "-d"
          root = val
        when "-f"
          glob = val
        when "-r"
          recurse = false if( val =~ /^(f|n|0)/i )
      end
    }
    
    if( not glob )
      print_error( "You must specify a valid file glob to search for, e.g. >search -f *.doc" )
      return
    end
    
    files = client.fs.file.search( root, glob, recurse )
    
    if( not files.empty? )
      print_line( "Found #{files.length} result#{ files.length > 1 ? 's' : '' }..." )
      files.each do | file |
        if( file['size'] > 0 )
          print( " #{file['path']}#{ file['path'].empty? ? '' : '\\' }#{file['name']} (#{file['size']} bytes)\n" )
        else
          print( " #{file['path']}#{ file['path'].empty? ? '' : '\\' }#{file['name']}\n" )
        end
      end
    else
      print_line( "No files matching your search were found." )
    end
    
  end
  
  #
  # Reads the contents of a file and prints them to the screen.
  #
  def cmd_cat(*args)
    if (args.length == 0)
      print_line("Usage: cat file")
      return true
    end
 begin 
      fd = client.fs.file.new(args[0], "rb")

      until fd.eof?
        print(fd.read)
      end

      fd.close
 rescue Errno::ENOENT
   print_error("File does not exist")
   return false
 end

    true
  end

  #
  # Change the working directory.
  #
  def cmd_cd(*args)
    if (args.length == 0)
      print_line("Usage: cd directory")
      return true
    end
 begin
      if args[0] =~ /\%(\w*)\%/
        client.fs.dir.chdir(client.fs.file.expand_path(args[0].upcase))
      else
        client.fs.dir.chdir(args[0])
      end

 rescue Errno::ENOENT
   print_error("Directory does not exist")
   return false
 rescue Errno::ENOTDIR
   print_error("Not a directory")
 end
    return true
  end

  #
  # Change the local working directory.
  #
  def cmd_lcd(*args)
    if (args.length == 0)
      print_line("Usage: lcd directory")
      return true
    end

    ::Dir.chdir(args[0])

    return true
  end
  
  #
  # Delete the specified file.
  #
  def cmd_rm(*args)
    if (args.length == 0)
      print_line("Usage: rm file")
      return true
    end

    client.fs.file.rm(args[0])

    return true
  end
  
  alias :cmd_del :cmd_rm

  def cmd_download_help
    print_line "Usage: download [options] src1 src2 src3 ... destination"
    print_line
    print_line "Downloads remote files and directories to the local machine."
    print_line @@download_opts.usage
  end
  
  #
  # Downloads a file or directory from the remote machine to the local
  # machine.
  #
  def cmd_download(*args)
    if (args.empty? or args.include? "-h")
      cmd_download_help
      return true
    end

    recursive = false
    src_items = []
    last   = nil
    dest   = nil

    @@download_opts.parse(args) { |opt, idx, val|
      case opt
      when "-r"
        recursive = true
      when nil
        src_items << last if (last)
        last = val
      end
    }

    # No files given, nothing to do
    if not last
      cmd_download_help
      return true
    end

    # Source and destination will be the same
    if src_items.empty?
      src_items << last
      # Use the basename of the remote filename so we don't end up with
      # a file named c:\\boot.ini in linux
      dest = ::Rex::Post::MetaSsh::Extensions::Stdapi::Fs::File.basename(last)
    else
      dest = last
    end

    # Go through each source item and download them
    src_items.each { |src|
      stat = client.fs.file.stat(src)

      if (stat.directory?)
        client.fs.dir.download(dest, src, recursive, true) { |step, src, dst|
          print_status("#{step.ljust(11)}: #{src} -> #{dst}")
          client.framework.events.on_session_download(client, src, dest) if msf_loaded?
        }
      elsif (stat.file?)
        client.fs.file.download(dest, src) { |step, src, dst|
          print_status("#{step.ljust(11)}: #{src} -> #{dst}")
          client.framework.events.on_session_download(client, src, dest) if msf_loaded?
        }
      end
    }
    
    return true
  end

  #
  # Downloads a file to a temporary file, spawns and editor, and then uploads
  # the contents to the remote machine after completion.
  #
  def cmd_edit(*args)
    if (args.length == 0)
      print_line("Usage: edit file")
      return true
    end

    # Get a temporary file path
    meterp_temp = Tempfile.new('metassh')
    meterp_temp.binmode
    temp_path = meterp_temp.path

    begin
      # Download the remote file to the temporary file
      client.fs.file.download_file(temp_path, args[0])
    rescue RequestError => re
      # If the file doesn't exist, then it's okay.  Otherwise, throw the
      # error.
      if re.result != 2
        raise $!
      end
    end

    # Spawn the editor (default to vi)
    editor = Rex::Compat.getenv('EDITOR') || 'vi'

    # If it succeeds, upload it to the remote side.
    if (system("#{editor} #{temp_path}") == true)
      client.fs.file.upload_file(args[0], temp_path)
    end

    # Get rid of that pesky temporary file
    temp_path.close(true)
  end

  #
  # Display the local working directory.
  #
  def cmd_lpwd(*args)
    print_line(::Dir.pwd)
    return true
  end

  alias cmd_getlwd cmd_lpwd

  #
  # Lists files
  #
  # TODO: make this more useful
  #
  def cmd_ls(*args)
    path = args[0] || client.fs.dir.getwd
    tbl  = Rex::Text::Table.new(
      'Header'  => "Listing: #{path}",
      'Columns' =>
        [
          'Mode',
          'Size',
          'Type',
          'Last modified',
          'Name',
        ])

    items = 0

    # Enumerate each item...
    client.fs.dir.entries_with_info(path).sort { |a,b| a['FileName'] <=> b['FileName'] }.each { |p|

      tbl <<
        [
          p['StatBuf'] ? p['StatBuf'].prettymode : '',
          p['StatBuf'] ? p['StatBuf'].size    : '',
          p['StatBuf'] ? p['StatBuf'].ftype[0,3] : '',
          p['StatBuf'] ? p['StatBuf'].mtime   : '',
          p['FileName'] || 'unknown'
        ]

      items += 1
    }

    if (items > 0)
      print("\n" + tbl.to_s + "\n")
    else
      print_line("No entries exist in #{path}")
    end

    return true
  end

  #
  # Make one or more directory.
  #
  def cmd_mkdir(*args)
    if (args.length == 0)
      print_line("Usage: mkdir dir1 dir2 dir3 ...")
      return true
    end

    args.each { |dir|
      print_line("Creating directory: #{dir}")

      client.fs.dir.mkdir(dir)
    }

    return true
  end

  #
  # Display the working directory.
  #
  def cmd_pwd(*args)
    print_line(client.fs.dir.getwd)
  end

  alias cmd_getwd cmd_pwd

  #
  # Removes one or more directory if it's empty.
  #
  def cmd_rmdir(*args)
    if (args.length == 0 or args.include?("-h"))
      print_line("Usage: rmdir dir1 dir2 dir3 ...")
      return true
    end

    args.each { |dir|
      print_line("Removing directory: #{dir}")
      client.fs.dir.rmdir(dir)
    }

    return true
  end

  def cmd_upload_help
    print_line "Usage: upload [options] src1 src2 src3 ... destination"
    print_line
    print_line "Uploads local files and directories to the remote machine."
    print_line @@upload_opts.usage
  end

  #
  # Uploads a file or directory to the remote machine from the local
  # machine.
  #
  def cmd_upload(*args)
    if (args.empty? or args.include?("-h"))
      cmd_upload_help
      return true
    end

    recursive = false
    src_items = []
    last   = nil
    dest   = nil

    @@upload_opts.parse(args) { |opt, idx, val|
      case opt
        when "-r"
          recursive = true
        when nil
          if (last)
            src_items << last
          end

          last = val
      end
    }

    return true if not last

    # Source and destination will be the same
    src_items << last if src_items.empty?

    dest = last

    # Go through each source item and upload them
    src_items.each { |src|
      stat = ::File.stat(src)

      if (stat.directory?)
        client.fs.dir.upload(dest, src, recursive) { |step, src, dst|
          print_status("#{step.ljust(11)}: #{src} -> #{dst}")
          client.framework.events.on_session_upload(client, src, dest) if msf_loaded?
        }
      elsif (stat.file?)
        client.fs.file.upload(dest, src) { |step, src, dst|
          print_status("#{step.ljust(11)}: #{src} -> #{dst}")
          client.framework.events.on_session_upload(client, src, dest) if msf_loaded?
        }
      end
    }
    
    return true
  end

  def cmd_upload_tabs(str, words)
    return [] if words.length > 1

    tab_complete_filenames(str, words)
  end

end

end
end
end
end
