#
# Copyright (c) 2007 RightScale Inc
# 
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
# 
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

class RightPhotoWorker
  
  def do_work(message_env, message)
  
    result = {}
    unless message_env['s3_download'].blank?
      puts "---\nOriginal message:\n#{message.inspect}\n---"
     
      photos_out_dir = message_env['s3_out']
      message_id     = message_env['message_id'].gsub('|','-')
      
      out_dir = "#{photos_out_dir}/#{Time.now.utc.strftime('%Y%m%d-%H%M%S')}"
      Dir.mkdir out_dir
      message_env['s3_download'].each do |photo|
        in_file  = "#{message_env['s3_in']}/#{File.basename(photo)}"
        out_file = "#{out_dir}/#{File.basename(photo)}"
        puts       " - Starting image '#{File.basename(photo)}' conversion:"
        exec_cmd("/usr/bin/convert -resize 800x800 -sharpen 2 -raise 7x7 -sepia-tone 80% -verbose #{in_file} #{out_file}")
      end
      puts " - All conversions completed"
      
      result['audit_info'] = { :audit => 'RightPhotoWorker', 'files' => message_env['s3_download']}
      result['result'] = 0
    else
      result = {'result' => 0, 'audit_info' => 'no photos been given'}
    end
    
    result
  end


  def exec_cmd(cmd)
    puts "*** CMD: #{cmd}" 
    out = `#{cmd}`
    puts "*** OUT: #{out}" unless out.blank?
    out
  end

end