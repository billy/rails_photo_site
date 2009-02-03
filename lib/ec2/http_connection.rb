require "net/https"
require "uri"
require "time"

#-----------------------------------------------------------------
# HttpConnection - Maintain a persistent HTTP connection to a remote
# server. The tricky part is that HttpConnection tries to be smart
# about errors. It will retry a request a few times and then "refuse"
# to talk to the server for a while until it does one retry. The intent
# is that we don't want to stall for many seconds on every request if the
# remote server went down.
# In addition, the error retry algorithm is global, as opposed to
# per-thread, this means that if one thread discovers that there is a
# problem then other threads get an error immediately until the lock-out period
# is over.
#-----------------------------------------------------------------

# Timeouts
HTTP_CONNECTION_RETRY_COUNT   = 3   # Number of retries to perform on the first error encountered
HTTP_CONNECTION_OPEN_TIMEOUT  = 5   # Wait a short time when opening a connection
HTTP_CONNECTION_READ_TIMEOUT  = 30  # Wait a little longer for a response, the serv may have to "think", after all
HTTP_CONNECTION_RETRY_DELAY   = 15  # All requests during this period are disabled

class HttpConnection

  #--------------------
  # class methods
  #--------------------
  
  def self.logger; 
    return defined?(BACKGROUNDRB_LOGGER) ? BACKGROUNDRB_LOGGER : RAILS_DEFAULT_LOGGER; 
  end
  def logger; self.class.logger; end

  #------------------
  # instance methods
  #------------------
  attr_accessor :http
  attr_accessor :server

  def initialize
    @http = nil
    @server = nil
  end

private
  #--------------
  # Retry state - Keep track of errors on a per-server basis
  #--------------
  @@state = {}  # retry state indexed by server: consecutive error count, error time, and error

  # number of consecutive errors seen for server, 0 all is ok
  def error_count
    @@state[@server] ? @@state[@server][:count] : 0
  end
  
  # time of last error for server, nil if all is ok
  def error_time
    @@state[@server] && @@state[@server][:time]
  end
  
  # message for last error for server, "" if all is ok
  def error_message
    @@state[@server] ? @@state[@server][:message] : ""
  end
  
  # add an error for a server
  def error_add(message)
    @@state[@server] = { :count => error_count+1, :time => Time.now, :message => message }
  end
  
  # reset the error state for a server (i.e. a request succeeded)
  def error_reset
    @@state.delete(@server)
  end
  
  # Error message stuff...
  
  def banana_message
    return "#{@server} temporarily unavailable: (#{error_message})"
  end

  def err_header
    return 'HttpConnection : '
  end
  
  #---------------------------------------------------------------------
  # Start a fresh connection. Close any existing one first.
  #---------------------------------------------------------------------
  def start(request_params)
    # close the previous if exists
    @http.finish if @http && @http.started?
    # create new connection
    @server = request_params[:server]
    @port   = request_params[:port]
    logger.info("Opening new HTTP connection to #{@server}")
    @http = Net::HTTP.new(@server, @port)
    @http.open_timeout = HTTP_CONNECTION_OPEN_TIMEOUT
    @http.read_timeout = HTTP_CONNECTION_READ_TIMEOUT
    if @port == 443
      verifyCallbackProc = Proc.new{ |ok, x509_store_ctx|
        code = x509_store_ctx.error
        msg = x509_store_ctx.error_string
          #debugger
        logger.warn("##### #{@server} certificate verify failed: #{msg}") unless code == 0
        true
      }
      @http.use_ssl         = true
      @http.verify_mode     = OpenSSL::SSL::VERIFY_PEER
      @http.verify_callback = verifyCallbackProc
      @http.ca_file = "#{RAILS_ROOT}/lib/ec2/f73e89fd.0"
    end
    # open connection
    @http.start
  end

public
  
  #-----------------------------
  # Send HTTP request to server
  #-----------------------------
    
  def request(request_params)
    loop do
      # if we are inside a delay between retries: no requests this time!
      if error_count > HTTP_CONNECTION_RETRY_COUNT \
      && error_time + HTTP_CONNECTION_RETRY_DELAY > Time.now
        logger.warn(err_header + " re-raising same error: #{banana_message} " +
                    "-- error count: #{error_count}, error age: #{Time.now - error_time}")  
        # TODO: figure out how to remove dependency on Ec2Error from this class...
        raise Ec2Error.new(banana_message)
      end
    
      # try to connect server(if connection does not exist) and get response data
      begin
        # (re)open connection to server if none exists
        start(request_params) unless @http
        
        # get response and return it
        request  = request_params[:request]
        request['User-Agent'] = 'www.RightScale.com'
        # if we reuse request due to connection problem it may have @body set already
        # this case - 'data' must be set to nil
        # (Also: see net/http.rb's set_body_internal)
        data     = (request.request_body_permitted? && request.body.nil?) ? request_params[:data] : nil
        response = @http.request(request, data)
        
        error_reset
        return response
      
      # EOFError means the server closed the connection on us, that's not a problem, we
      # just start a new one (without logging any error)
      rescue EOFError => e
        logger.debug(err_header + " server #{@server} closed connection")
        @http = nil
        
      rescue Exception => e  # See comment at bottom for the list of errors seen...
        # if ctrl+c is pressed - we have to reraise exception to terminate proggy 
        if e.is_a?(Interrupt) && !( e.is_a?(Errno::ETIMEDOUT) || e.is_a?(Timeout::Error))
          logger.debug(err_header + " request to server #{@server} interrupted by ctrl-c")
          @http = nil
          raise
        end
        # oops - we got a banana: log it
        error_add(e.message)
        logger.warn(err_header + " request failure count: #{error_count}, exception: #{e.inspect}")
        @http = nil
      end
    end
  end

# Errors received during testing:
#
#  #<Timeout::Error: execution expired>
#  #<Errno::ETIMEDOUT: Connection timed out - connect(2)>
#  #<SocketError: getaddrinfo: Name or service not known>
#  #<SocketError: getaddrinfo: Temporary failure in name resolution>
#  #<EOFError: end of file reached>
#  #<Errno::ECONNRESET: Connection reset by peer>
#  #<OpenSSL::SSL::SSLError: SSL_write:: bad write retry>
end

