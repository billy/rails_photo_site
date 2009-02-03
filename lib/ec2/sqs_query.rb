require 'lib/ec2/ec2_query_native'

  # Implements RightScale type interface to Amazon SQS
  # In any errors raises Ec2Error
  #
  #  --- QUEUEs methods
  #  create_queue(queue_name, default_visibility_timeout=nil)
  #  list_queues(queue_name_prefix=nil)
  #  delete_queue(queue_url)
  #  --- QUEUEs helper methods
  #  queue_url_by_name(queue_name)
  #  queue_name_by_url(queue_url)
  #  get_queue_length(queue_url)
  #  clear_queue(queue_url)
  #  force_delete_queue(queue_url)
  #
  #  --- TIMEOUTs  methods
  #  set_visibility_timeout(queue_url, visibility_timeout=nil)
  #  get_visibility_timeout(queue_url)
  #
  #  --- PERMISSIONs methods
  #  add_grant(queue_url, grantee_email_address, permission = nil)
  #  list_grants(queue_url, grantee_email_address=nil, permission = nil)
  #  remove_grant(queue_url, grantee_email_address_or_id, permission = nil)
  #
  #  --- MESSAGESs methods
  #  receive_messages(queue_url, number_of_messages=1, visibility_timeout=nil)
  #  peek_message(queue_url, message_id)
  #  send_message(queue_url, message)
  #  delete_message(queue_url, message_id)
  #
  #  --- MESSAGESs helper methods
  #  receive_message(queue_url, visibility_timeout=nil)
  #  alias_method :push_message, :send_message
  #  pop_messages(queue_url, number_of_messages=1)
  #  pop_message(queue_url)
  #


class SqsQuery
  
  SIGNATURE_VERSION = "1"
  API_VERSION       = "2006-04-01"
  DEFAULT_HOST      = "queue.amazonaws.com"
  DEFAULT_PORT      = 443
  DEFAULT_VISIBILITY_TIMEOUT = 30
  REQUEST_TTL       = 30

  attr_accessor :multi_thread
  attr_accessor :aws_access_key_id
  attr_accessor :last_request, :last_response
  
  @@bench_sqs = Benchmark::Tms.new()
  @@bench_xml = Benchmark::Tms.new()
  def self.bench_sqs; @@bench_sqs; end
  def self.bench_xml; @@bench_xml; end

  def initialize(aws_access_key_id, aws_secret_access_key, server=DEFAULT_HOST, port=DEFAULT_PORT)
    raise Ec2Error.new("AWS access keys are required to operate on SQS") \
      if aws_access_key_id.blank? || aws_secret_access_key.blank?
    @aws_access_key_id     = aws_access_key_id
    @aws_secret_access_key = aws_secret_access_key
    @aws_server            = server
    @aws_port              = port
    @multi_thread          = defined?(BACKGROUNDRB_LOGGER) || defined?(AWS_DAEMON)
    RAILS_DEFAULT_LOGGER.info("New SqsQuery using #{@multi_thread ? 'multi' : 'single'}-threaded mode")
  end
  
#-----------------------------------------------------------------
#      Requests
#-----------------------------------------------------------------

    # Generates request hash for QUERY API
  def generate_request(action, param={})
      # Sometimes we need to use queue uri (delete queue etc)
      # In that case we will use Symbol key: 'param[:queue_url]'
    queue_uri = param[:queue_url] ? URI(param[:queue_url]).path : '/'
      # remove unset(=optional) and symbolyc keys
    param.each{ |key, value| param.delete(key) if (value.nil? || key.is_a?(Symbol)) }
      # prepare output hash
    request_hash = { "Action"           => action,
                     "Expires"          => Time.now.utc.since(REQUEST_TTL).strftime("%Y-%m-%dT%H:%M:%SZ"),
                     "AWSAccessKeyId"   => @aws_access_key_id,
                     "Version"          => API_VERSION,
                     "SignatureVersion" => SIGNATURE_VERSION }
    request_hash.update(param)
    request_data   = request_hash.sort{|a,b| (a[0].to_s.downcase)<=>(b[0].to_s.downcase)}.to_s
    request_hash['Signature'] = Base64.encode64( OpenSSL::HMAC.digest( OpenSSL::Digest::Digest.new( "sha1" ), @aws_secret_access_key, request_data)).strip
    request_params = request_hash.to_a.collect{|key,val| key.to_s + "=" + CGI::escape(val.to_s) }.join("&")
    request        = Net::HTTP::Get.new("#{queue_uri}?#{request_params}")
      # prepare output hash
    { :request => request, 
      :server  => @aws_server,
      :port    => @aws_port,
      :data    => nil }
  end

    # Generates request hash for REST API
  def generate_rest_request(method, param)
    queue_uri = URI(param[:queue_url]).path    # extract queue_url from param
    message   = param[:message]                # extract message body if nesessary
      # remove unset(=optional) and symbolyc keys
    param.each{ |key, value| param.delete(key) if (value.nil? || key.is_a?(Symbol)) }
      # created request
    param_to_str = param.to_a.collect{|key,val| key.to_s + "=" + CGI::escape(val.to_s) }.join("&")
    param_to_str = "?#{param_to_str}" unless param_to_str.blank?
    request = "Net::HTTP::#{method.titleize}".constantize.new("#{queue_uri}#{param_to_str}")
      # set main headers
    request['content-md5']  = ''
    request['Content-Type'] = 'text/plain'
    request['Date']         = Time.now.httpdate
      # generate authorization string
    auth_string = "#{method.upcase}\n#{request['content-md5']}\n#{request['Content-Type']}\n#{request['Date']}\n#{CGI::unescape(queue_uri)}"
    signature   = Base64.encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::Digest.new("sha1"), @aws_secret_access_key, auth_string)).strip
      # set other headers
    request['Authorization'] = "AWS #{@aws_access_key_id}:#{signature}"
    request['AWS-Version']   = API_VERSION
      # prepare output hash
    { :request => request, 
      :server  => @aws_server,
      :port    => @aws_port,
      :data    => message }
  end

    # Sends request to Amazon and parses the response
    # Raises Ec2Error if any banana happened
  def request_info(request, parser)
    thread = @multi_thread ? Thread.current : Thread.main
    thread[:sqs_connection] ||= HttpConnection.new
    @last_request  = request[:request].path
    @last_response = nil
    
    response=nil
    @@bench_sqs.add!{ response = thread[:sqs_connection].request(request) }
      # check response for errors...
    if response.is_a?(Net::HTTPSuccess)
      @last_response = response.body
      @@bench_xml.add!{ REXML::Document.parse_stream(response.body, parser) }
      parser.result
    else
      RAILS_DEFAULT_LOGGER.warn("##### SQS returned an error: #{response.code} #{response.message}\n#{response.body} #####")
      RAILS_DEFAULT_LOGGER.warn("##### SQS request: #{request[:server]}:#{request[:port]}#{request[:request].path} ####")
      @last_response = "#{response.code} -- #{response.message} -- #{response.body}"
      @@bench_xml.add! do
        parser = QEc2_ErrorResponseParser.new
        REXML::Document.parse_stream(response.body, parser)
      end
        # if error is in request params ('Invalid URI' or something else) that case Ec2Error.errors is empty...
      parser.errors << [response.code, response.message] if parser.errors.blank?
      raise Ec2Error.new('', response.code, parser.errors, parser.requestID)
    end
  end

#-----------------------------------------------------------------
#      Queues
#-----------------------------------------------------------------

   # QUERY API: Creates new queue.
   # Returns queue url if OK, else raises an error
  def create_queue(queue_name, default_visibility_timeout=nil)
    req_hash = generate_request('CreateQueue', 
                                'QueueName'                => queue_name,
                                'DefaultVisibilityTimeout' => default_visibility_timeout || DEFAULT_VISIBILITY_TIMEOUT )
    request_info(req_hash, SqsCreateQueueParser.new)
  end

   # QUERY API: Creates new queue.
   # Returns an array of queue urls (raises error if banana)
  def list_queues(queue_name_prefix=nil)
    req_hash = generate_request('ListQueues', 'QueueNamePrefix' => queue_name_prefix)
    request_info(req_hash, SqsListQueuesParser.new)
  end
    
    # QUERY API: Deletes queue (queue must have no messages!)
    # Returns true or raises an exception
  def delete_queue(queue_url)
    req_hash = generate_request('DeleteQueue', :queue_url => queue_url)
    request_info(req_hash, SqsStatusParser.new)
  end

#-----------------------------------------------------------------
#      Timeouts
#-----------------------------------------------------------------

   # QUERY API: Sets visibility timeout.
   # Returns true if OK else raises an error
  def set_visibility_timeout(queue_url, visibility_timeout=nil)
    req_hash = generate_request('SetVisibilityTimeout', 
                                'VisibilityTimeout' => visibility_timeout || DEFAULT_VISIBILITY_TIMEOUT,
                                :queue_url => queue_url )
    request_info(req_hash, SqsStatusParser.new)
  end

   # QUERY API: Returns visibility timeout for given queue (integer)
  def get_visibility_timeout(queue_url)
    req_hash = generate_request('GetVisibilityTimeout', :queue_url => queue_url )
    request_info(req_hash, SqsGetVisibilityTimeoutParser.new)
  end

#-----------------------------------------------------------------
#      Permissions
#-----------------------------------------------------------------

   # QUERY API: Adds grants for user (identified by email he registered at Amazon)
   # Returns true if OK else raises an error
  def add_grant(queue_url, grantee_email_address, permission = nil)
    req_hash = generate_request('AddGrant', 
                                'Grantee.EmailAddress' => grantee_email_address,
                                'Permission'           => permission,
                                :queue_url             => queue_url)
    request_info(req_hash, SqsStatusParser.new)
  end
  
    # QUERY API: Returns hash of grantee_id=>perms for this queue:
    # :grantee_id => {:name=>string, :perms=>['FULLCONTROL','RECEIVEMESSAGE','SENDMESSAGE']}  
  def list_grants(queue_url, grantee_email_address=nil, permission = nil)
    req_hash = generate_request('ListGrants', 
                                'Grantee.EmailAddress' => grantee_email_address,
                                'Permission'           => permission,
                                :queue_url             => queue_url)
    response = request_info(req_hash, SqsListGrantsParser.new)
      # One user may have up to 3 permission records for every queue.
      # We will join these records to one.
    result = {}    
    response.each do |perm|
      id = perm[:id]
        # create hash for new user if unexisit
      result[id] = {:perms=>[]} unless result[id]
        # fill current grantee params
      result[id][:perms] << perm[:permission]
      result[id][:name] = perm[:name]
    end
    result
  end

    # QUERY API: Revokes permission from user
    # Returns true if OK else - error
  def remove_grant(queue_url, grantee_email_address_or_id, permission = nil)
    grantee_key = grantee_email_address_or_id.include?('@') ? 'Grantee.EmailAddress' : 'Grantee.ID'
    req_hash = generate_request('RemoveGrant', 
                                grantee_key  => grantee_email_address_or_id,
                                'Permission' => permission,
                                :queue_url   => queue_url)
    request_info(req_hash, SqsStatusParser.new)
  end

#-----------------------------------------------------------------
#      Messages
#-----------------------------------------------------------------
  
    # REST API: Reads a list of messages from queue
    # Returns a list of hashes: {:id=>'message_id', body=>'message_body'}
  def receive_messages(queue_url, number_of_messages=1, visibility_timeout=nil)
    return [] if number_of_messages == 0
    req_hash = generate_rest_request('GET',
                                     'NumberOfMessages'  => number_of_messages,
                                     'VisibilityTimeout' => visibility_timeout,
                                     :queue_url          => "#{queue_url}/front" )
    request_info(req_hash, SqsReceiveMessagesParser.new)
  end
  
    # REST API: Peeks message from queue
    # Returns message in format of {:id=>'message_id', :body=>'message_body'} or nil
  def peek_message(queue_url, message_id)
    req_hash = generate_rest_request('GET', :queue_url => "#{queue_url}/#{CGI::escape message_id}" )
    messages = request_info(req_hash, SqsReceiveMessagesParser.new)
    messages.blank? ? nil : messages[0]
  end

    # REST API: Sends message to queue
    # Returns 'message_id' or raises an exception
  def send_message(queue_url, message)
    req_hash = generate_rest_request('PUT',
                                     :message   => message,
                                     :queue_url => "#{queue_url}/back")
    request_info(req_hash, SqsSendMessagesParser.new)
  end
  
    # QUERY API: Deletes message from queue
    # Returns true or raises an exception
  def delete_message(queue_url, message_id)
    req_hash = generate_request('DeleteMessage', 
                                'MessageId' => message_id,
                                :queue_url  => queue_url)
    request_info(req_hash, SqsStatusParser.new)
  end
  
#-----------------------------------------------------------------
#      Other (helper) methods
#-----------------------------------------------------------------
    #----------
    #  QUQUEs 
    #----------
    # Returns queue url by queue short name or nil if queue is not found
  def queue_url_by_name(queue_name)
    return queue_name if queue_name.include?('/')
    queue_urls = list_queues(queue_name)
    queue_urls.each do |queue_url|
      return queue_url if queue_name_by_url(queue_url) == queue_name
    end
    nil
  end

    # Returns short queue name by url
  def self.queue_name_by_url(queue_url)
    queue_url[/[^\/]*$/]
  end
  
  def queue_name_by_url(queue_url)
    self.class.queue_name_by_url(queue_url)
  end
  
    # Returns approximate amount of messages in queue
  def get_queue_length(queue_url)
    stop_at = Time.now.since(5.seconds)
    count   = 0
    while (msgs = receive_messages(queue_url, 100, (stop_at-Time.now).to_i+1)).length > 0
      count += msgs.size
      break if Time.now >= stop_at
    end
    count
  end

    # Removes all messages from queue
    # Return true or raises an exception
  def clear_queue(queue_url)
    while (m = pop_message(queue_url)) ; end   # delete all messages in queue
    true
  end
  
    # Removes all messages from queue then deletes queue
    # Return true if queue been deleted else raises an exception
  def force_delete_queue(queue_url)
    clear_queue(queue_url)
    delete_queue(queue_url)
  end

    #------------
    #  MESSAGEs
    #------------
    # Reads first accessible message from queue
    # Returns message as hash {:id=>'message_id', :body=>'message_body'} or nil
  def receive_message(queue_url, visibility_timeout=nil)
    result = receive_messages(queue_url, 1, visibility_timeout)
    result.blank? ? nil : result[0]
  end
  
    # Same as send_message
  alias_method :push_message, :send_message
  
    # Pops (deletes) up to 'number_of_messages' from queue
    # Returns an array of messages in format of [{:id=>'message_id', :body=>'message_body'}] or empty array
  def pop_messages(queue_url, number_of_messages=1)
    messages = receive_messages(queue_url, number_of_messages)
    messages.each do |message|
      delete_message(queue_url, message[:id])
    end
    messages
  end

    # Pops (deletes) first accessible message from queue
    # Returns message in format of {:id=>'message_id', :body=>'message_body'} or nil
  def pop_message(queue_url)
    messages = pop_messages(queue_url)
    messages.blank? ? nil : messages[0]
  end

  #-----------------------------------------------------------------
  #      PARSERS: the parent to all others SQS parsers
  #-----------------------------------------------------------------

  class SqsParser < QEc2_Parser ; end

  #-----------------------------------------------------------------
  #      PARSERS: Status Response Parser
  #-----------------------------------------------------------------

  class SqsStatusParser < SqsParser 
    def tagend(name)
      if name == 'StatusCode'
        @result = @text=='Success' ? true : false
      end
    end
  end

  #-----------------------------------------------------------------
  #      PARSERS: Queue
  #-----------------------------------------------------------------

  class SqsCreateQueueParser < SqsParser
    def tagend(name)
      @result = @text if name == 'QueueUrl'
    end
  end

  class SqsListQueuesParser < SqsParser
    def reset
      @result = []
    end
    def tagend(name)
      @result << @text if name == 'QueueUrl'
    end
  end

  #-----------------------------------------------------------------
  #      PARSERS: Timeouts
  #-----------------------------------------------------------------

  class SqsGetVisibilityTimeoutParser < SqsParser
    def tagend(name)
      @result = @text.to_i if name == 'VisibilityTimeout'
    end
  end

  #-----------------------------------------------------------------
  #      PARSERS: Permissions
  #-----------------------------------------------------------------

  class SqsListGrantsParser < SqsParser
    def reset
      @result = []
    end
    def tagstart(name, attributes)
      @current_perms = {} if name == 'GrantList'
    end
    def tagend(name)
      case name
        when 'ID'         ; @current_perms[:id]         = @text
        when 'DisplayName'; @current_perms[:name]       = @text
        when 'Permission' ; @current_perms[:permission] = @text
        when 'GrantList'  ; @result << @current_perms 
      end
    end
  end

  #-----------------------------------------------------------------
  #      PARSERS: Messages
  #-----------------------------------------------------------------

  class SqsReceiveMessagesParser < SqsParser
    def reset
      @result = []
    end
    def tagstart(name, attributes)
      @current_message = {} if name == 'Message'
    end
    def tagend(name)
      case name
        when 'MessageId'  ; @current_message[:id]   = @text
        when 'MessageBody'; @current_message[:body] = @text
        when 'Message'    ; @result << @current_message
      end
    end
  end

  class SqsSendMessagesParser < SqsParser
    def tagend(name)
      @result = @text if name == 'MessageId'
    end
  end
  
end