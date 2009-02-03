####
# Copyright (c) 2007 RightScale, Inc, All Rights Reserved Worldwide.
#
# THIS PROGRAM IS CONFIDENTIAL AND PROPRIETARY TO RIGHTSCALE
# AND CONSTITUTES A VALUABLE TRADE SECRET.  Any unauthorized use,
# reproduction, modification, or disclosure of this program is
# strictly prohibited.  Any use of this program by an authorized
# licensee is strictly subject to the terms and conditions,
# including confidentiality obligations, set forth in the applicable
# License Agreement between RightScale.com, Inc. and
# the licensee.
#
# Handler for status/health checks.
# Load balancers (or other machines for that matter) will be able to monitor the health of
# each mongrel by retrieving a successful response from this handler
# This file can be included in the configuration of the mongrels (i.e., mongrel_cluster.yml)
# config_script: lib/mongrel_health_check_handler.rb
#
# Josep M. Blanquer
# August 30, 2007
#

# This must be called from a Mongrel configuration...
class MongrelHealthCheckHandler < Mongrel::HttpHandler
  def initialize
    #Make sure it's expired by the time we process the first request
    @lastcheck= Time.now() - 3600
    @freshness= 30
  end
  def process(request,response)
    response.start(200) do |head,out|
      head["Content-Type"] = "text/html"
      t = Time.now
      # Just mark a variable true if it's time to do a more heavyweight check (i.e., rails or DB...)
      # but not do anything at this moment.
      perform_extra_check=true if( (t-@lastcheck).to_i > @freshness )

      out.write "Hello. NOW[#{t}] elapsed[#{(t-@lastcheck).to_i}s]"
    end
  end
end

uri "/mongrel-status", :handler => MongrelHealthCheckHandler.new, :in_front => true
