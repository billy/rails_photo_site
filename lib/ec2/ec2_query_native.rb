require "cgi"
require "base64"
require "net/https"
require "rexml/document"

require "openssl"
require "digest/sha1"
require "uri"
require "time"
require "lib/ec2/http_connection"
require 'benchmark'


# A hack because there's a bug in add! in Benchmark::Tms
module Benchmark
  class Tms
    def add!(&blk)
      t = Benchmark::measure(&blk)
      @utime  = utime + t.utime
      @stime  = stime + t.stime
      @cutime = cutime + t.cutime
      @cstime = cstime + t.cstime
      @real   = real + t.real
      self
    end
  end
end


SIGNATURE_VERSION = "1"
#API_VERSION       = "2006-10-01"
#API_VERSION       = "2007-01-03"
API_VERSION       = "2007-01-19"
DEFAULT_HOST      = "ec2.amazonaws.com"
DEFAULT_PORT      = 443;
#DEFAULT_HOST      = "207.154.101.202"
EC2_DEFAULT_ADDRESSING_TYPE =  'public'
EC2_DNS_ADDRESSING_SET      = ['public','direct']

# Exception for errors returned by EC2
class Ec2Error < RuntimeError;
  attr_accessor :errors
  attr_accessor :errors_str
  attr_accessor :requestID
  attr_accessor :http_code
  
  def initialize(msg='', http_code=0, errors=[], requestID='')
    @errors     = errors
    @requestID  = requestID
    @http_code  = http_code
    @errors_str = errors.map{|code, msg| "#{code}: #{msg}"}.join("; ")
    super(msg)
  end
  
  def include?(pattern)
    @errors.each{ |code, msg| return true if code =~ pattern }
    return false
  end
end

class Ec2_NativeQuery
  attr_accessor :multi_thread
  attr_accessor :aws_access_key_id
  attr_accessor :last_request, :last_response
  
  @@bench_ec2 = Benchmark::Tms.new()
  @@bench_xml = Benchmark::Tms.new()
  def self.bench_ec2; @@bench_ec2; end
  def self.bench_xml; @@bench_xml; end

  def initialize(aws_access_key_id, aws_secret_access_key, server=DEFAULT_HOST, port=DEFAULT_PORT)
    raise Ec2Error.new("AWS access keys are required to operate on EC2") \
      if aws_access_key_id.blank? || aws_secret_access_key.blank?
    @aws_access_key_id     = aws_access_key_id
    @aws_secret_access_key = aws_secret_access_key
    @aws_server            = server
    @aws_port              = port
    @multi_thread          = defined?(BACKGROUNDRB_LOGGER) || defined?(AWS_DAEMON)
    RAILS_DEFAULT_LOGGER.info("New Ec2NativeQuery using #{@multi_thread ? 'multi' : 'single'}-threaded mode")
  end
  
  def generate_request(action, param={})
    timestamp    = ( Time::now ).utc.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    request_hash = {"Action"            => action,
                    "AWSAccessKeyId"    => @aws_access_key_id,
                    "Version"           => API_VERSION,
                    "Timestamp"         => timestamp,
                    "SignatureVersion"  => SIGNATURE_VERSION }
    request_hash.update(param)
    request_data   = request_hash.sort{|a,b| (a[0].to_s.downcase)<=>(b[0].to_s.downcase)}.to_s
    request_hash.update('Signature' => Base64.encode64( OpenSSL::HMAC.digest( OpenSSL::Digest::Digest.new( "sha1" ), @aws_secret_access_key, request_data)).strip)
    request_params = request_hash.to_a.collect{|key,val| key + "=" + CGI::escape(val) }.join("&")
    request        = Net::HTTP::Get.new("/?#{request_params}")
    
    params_list    = { :request => request, 
                       :server  => @aws_server,
                       :port    => @aws_port,
                       :data    => '' }
  end

  def request_info(request_params, parser)
    thread = @multi_thread ? Thread.current : Thread.main
    thread[:ec2_connection] ||= HttpConnection.new
    #RAILS_DEFAULT_LOGGER.info("HTTP REQUEST: #{request_params[:request].path}")
    @last_request = request_params[:request].path
    @last_response = nil
    response = nil

    @@bench_ec2.add!{ response = thread[:ec2_connection].request(request_params) }
    
    if response.is_a?(Net::HTTPSuccess)
      #RAILS_DEFAULT_LOGGER.info("HTTP RESPONSE: #{response.body}")
      @last_response = response.body
      result = nil
      @@bench_xml.add! do
        REXML::Document.parse_stream(response.body, parser)
        result = parser.result
      end
      result
    else
      RAILS_DEFAULT_LOGGER.warn("##### EC2 returned an error: #{response.code} #{response.message}\n#{response.body} #####")
      RAILS_DEFAULT_LOGGER.warn("##### EC2 request: #{request_params[:server]}:#{request_params[:port]}#{request_params[:request].path} ####")
      @last_response = "#{response.code} -- #{response.message} -- #{response.body}"
      @@bench_xml.add! do
        parser = QEc2_ErrorResponseParser.new
        REXML::Document.parse_stream(response.body, parser)
      end
      raise Ec2Error.new('', response.code, parser.errors, parser.requestID)
    end
  end

  def hash_params(prefix, list)
    groups = {}
    list.each_index{|i| groups.update("#{prefix}.#{i+1}"=>list[i])} if list
    return groups
  end

#-----------------------------------------------------------------

  def describe_key_pairs(list)
    link   = generate_request("DescribeKeyPairs", hash_params('KeyName',list))
    request_info(link, QEc2_DescribeKeyPairParser.new)
  end

  def create_key_pair(keyName)
    link   = generate_request("CreateKeyPair", 
                              'KeyName' => keyName.to_s)
    return request_info(link, QEc2_CreateKeyPairParser.new)
  end

  def delete_key_pair(keyName)
    link   = generate_request("DeleteKeyPair", 
                              'KeyName' => keyName.to_s)
    return request_info(link, QEc2_BoolResponseParser.new)
  end
    

#-----------------------------------------------------------------

  def describe_security_groups(list)
    link   = generate_request("DescribeSecurityGroups", hash_params('GroupName',list))
    return request_info(link, QEc2_DescribeSecurityGroupsParser.new)
  end

  def create_security_group(groupName, groupDescription='')
    # EC2 doesn't like an empty description...
    description = groupDescription.blank? ? " " : groupDescription.to_s
    link   = generate_request("CreateSecurityGroup", 
                              'GroupName'        => groupName.to_s, 
                              'GroupDescription' => description)
    return request_info(link, QEc2_BoolResponseParser.new)
  end

  def delete_security_group(groupName)
    link   = generate_request("DeleteSecurityGroup", 
                              'GroupName'        => groupName.to_s)
    return request_info(link, QEc2_BoolResponseParser.new)
  end

  def autorize_security_group_ingress_IP(groupName, ipProtocol='tcp', fromPort=0, toPort=65535, cidrIp='0.0.0.0/0')
    link   = generate_request("AuthorizeSecurityGroupIngress", 
                             'GroupName'  => groupName.to_s, 
                             'IpProtocol' => ipProtocol.to_s, 
                             'FromPort'   => fromPort.to_s, 
                             'ToPort'     => toPort.to_s, 
                             'CidrIp'     => cidrIp.to_s)
    return request_info(link, QEc2_BoolResponseParser.new)
  end

  def revoke_security_group_ingress_IP(groupName, ipProtocol='tcp', fromPort=0, toPort=65535, cidrIp='0.0.0.0/0')
    link   = generate_request("RevokeSecurityGroupIngress", 
                             'GroupName'  => groupName.to_s, 
                             'IpProtocol' => ipProtocol.to_s, 
                             'FromPort'   => fromPort.to_s, 
                             'ToPort'     => toPort.to_s, 
                             'CidrIp'     => cidrIp.to_s)
    return request_info(link, QEc2_BoolResponseParser.new)
  end

  def autorize_security_group_ingress_named(groupName, sourceSecurityGroupName, sourceSecurityGroupOwnerId)
    link   = generate_request("AuthorizeSecurityGroupIngress", 
                              'GroupName'                  => groupName.to_s, 
                              'SourceSecurityGroupName'    => sourceSecurityGroupName.to_s, 
                              'SourceSecurityGroupOwnerId' => sourceSecurityGroupOwnerId.to_s.gsub(/-/,''))
    return request_info(link, QEc2_BoolResponseParser.new)
  end

  def revoke_security_group_ingress_named(groupName, sourceSecurityGroupName, sourceSecurityGroupOwnerId)
    link   = generate_request("RevokeSecurityGroupIngress", 
                              'GroupName'                  => groupName.to_s, 
                              'SourceSecurityGroupName'    => sourceSecurityGroupName.to_s, 
                              'SourceSecurityGroupOwnerId' => sourceSecurityGroupOwnerId.to_s)
    return request_info(link, QEc2_BoolResponseParser.new)
  end

#-----------------------------------------------------------------

  def describe_images(type, list)
    link   = generate_request("DescribeImages", hash_params(type,list))
    return request_info(link, QEc2_DescribeImagesParser.new)
  end

  def describe_images_by_id( list)
    return describe_images('ImageId', list)
  end

  def describe_images_by_owner(list)
    return describe_images('Owner', list)
  end

  def describe_images_by_executable_by(list)
    return describe_images('ExecutableBy', list)
  end

  def register_image(imageLocation)
    link   = generate_request("RegisterImage", 
                              'ImageLocation' => imageLocation.to_s)
    return request_info(link, QEc2_RegisterImageParser.new)
  end

  def deregister_image(imageId)
    link   = generate_request("DeregisterImage", 
                              'ImageId' => imageId.to_s)
    return request_info(link, QEc2_BoolResponseParser.new)
  end

#-----------------------------------------------------------------

  def describe_image_attribute(imageId, attribute)
    link   = generate_request("DescribeImageAttribute", 
                              'ImageId'   => imageId,
                              'Attribute' => attribute)
    return request_info(link, QEc2_DescribeImageAttributeParser.new)
  end

  def reset_image_attribute(imageId, attribute)
    link   = generate_request("ResetImageAttribute", 
                              'ImageId'   => imageId,
                              'Attribute' => attribute)
    return request_info(link, QEc2_BoolResponseParser.new)
  end

  def modify_image_attribute(imageId, attribute, operationType, userId, userGroup)
    params =  {'ImageId'      => imageId,
              'Attribute'     => attribute,
              'OperationType' => operationType}
    params.update(hash_params('UserId',    userId))    if !userId.empty?
    params.update(hash_params('UserGroup', userGroup)) if !userGroup.empty?
    link   = generate_request("ModifyImageAttribute", params)
    return request_info(link, QEc2_BoolResponseParser.new)
  end

#-----------------------------------------------------------------

  def describe_instances(list)
    link   = generate_request("DescribeInstances", hash_params('InstanceId',list))
    return request_info(link, QEc2_DescribeInstancesParser.new)
  end

  def run_instances(imageId, minCount, maxCount, keyName, securityGroups, userData='', addressingType=EC2_DEFAULT_ADDRESSING_TYPE)
    # careful: keyName and securityGroups may be nil
    params = hash_params('SecurityGroup', securityGroups)
    params.update( {'ImageId' => imageId,
                    'MinCount' => minCount.to_s,
                    'MaxCount' => maxCount.to_s,
                    'AddressingType' => addressingType })
    params['KeyName']  = keyName if !keyName.blank?
    if !userData.blank?
      userData.strip!
        # Do not use CGI::escape(encode64(...)) as it is done in Amazons EC2 library.
        # Amazon 169.254.169.254 does not like escaped symbols!
        # And it dont like "\n" inside of encoded string! Grrr....
        # Otherwise, some of UserData symbols will be lost...
      params['UserData'] = Base64.encode64(userData).delete("\n") if !userData.empty?
    end
    link   = generate_request("RunInstances", params)
    return request_info(link, QEc2_RunInstancesParser.new)
  end

  def terminate_instances(list)
    link   = generate_request("TerminateInstances", hash_params('InstanceId',list))
    return request_info(link, QEc2_TerminateInstancesParser.new)
  end

  def get_console_output(instanceId)
    link   = generate_request("GetConsoleOutput", { 'InstanceId.1' => instanceId })
    return request_info(link, QEc2_GetConsoleOutputParser.new)
  end

  def reboot_instances(list)
    link   = generate_request("RebootInstances", hash_params('InstanceId',list))
    return request_info(link, QEc2_BoolResponseParser.new)
  end

end


#-----------------------------------------------------------------
#      PARSERS: the parent to all others ec2 parsers
#-----------------------------------------------------------------

class QEc2_Parser
  attr_accessor :result
  attr_reader   :xmlpath
  def initialize
    @xmlpath = ''
    @result  = false
    @text    = ''
    reset
  end
  def tag_start(name, attributes)
    @text = ''
    tagstart(name, attributes)
    @xmlpath += @xmlpath.empty? ? name : "/#{name}"
  end
  def tag_end(name)
    @xmlpath[/^(.*?)\/?#{name}$/]
    @xmlpath = $1
    tagend(name)
  end
  def text(text)
    @text = text
    tagtext(text)
  end
    # Parser must have a lots of methods 
    # (see /usr/lib/ruby/1.8/rexml/parsers/streamparser.rb)
    # We dont need most of them in QEc2_Parser and method_missing helps us
    # to skip their definition
  def method_missing(method, *params)
      # if the method is one of known - just skip it ...
    return if [:comment, :attlistdecl, :notationdecl, :elementdecl, 
               :entitydecl, :cdata, :xmldecl, :attlistdecl, :instruction, 
               :doctype].include?(method)
      # ... else - call super to raise an exception
    super(method, params)
  end
  
    # the functions to be overriden by children (if nessesery)
  def reset                     ; end
  def tagstart(name, attributes); end
  def tagend(name)              ; end
  def tagtext(text)             ; end
end


#-----------------------------------------------------------------
#      PARSERS: Errors
#-----------------------------------------------------------------

class QEc2_ErrorResponseParser < QEc2_Parser
    attr_accessor :errors  # array of hashes: error/message
    attr_accessor :requestID
  def tagend(name)
    case name
      when 'RequestID' ; @requestID = @text
      when 'Code'      ; @code      = @text
      when 'Message'   ; @message   = @text
      when 'Error'     ; @errors   << [ @code, @message ]
    end
  end
  def reset
    @errors = []
  end
end

#-----------------------------------------------------------------
#      PARSERS: Boolean Response Parser
#-----------------------------------------------------------------
  
class QEc2_BoolResponseParser < QEc2_Parser
  def tagend(name)
    @result = @text=='true' ? true : false if name == 'return'
  end
end

#-----------------------------------------------------------------
#      PARSERS: Key Pair
#-----------------------------------------------------------------

class QEc2_DescribeKeyPairType
  attr_accessor :keyName 
  attr_accessor :keyFingerprint
end

class QEc2_CreateKeyPairType < QEc2_DescribeKeyPairType
  attr_accessor :keyMaterial
end

class QEc2_DescribeKeyPairParser < QEc2_Parser
  def tagstart(name, attributes)
    @item = QEc2_DescribeKeyPairType.new if name == 'item'
  end
  def tagend(name)
    case name 
      when 'keyName'       ; @item.keyName        = @text
      when 'keyFingerprint'; @item.keyFingerprint = @text
      when 'item'          ; @result             << @item
    end
  end
  def reset
    @result = [];    
  end
end

class QEc2_CreateKeyPairParser < QEc2_Parser
  def tagstart(name, attributes)
    @result = QEc2_CreateKeyPairType.new if !@result
  end
  def tagend(name)
    case name 
      when 'keyName'        ; @result.keyName        = @text
      when 'keyFingerprint' ; @result.keyFingerprint = @text
      when 'keyMaterial'    ; @result.keyMaterial    = @text
    end
  end
end

#-----------------------------------------------------------------
#      PARSERS: Security Groups
#-----------------------------------------------------------------

class QEc2_UserIdGroupPairType
  attr_accessor :userId
  attr_accessor :groupName
end

class QEc2_IpPermissionType
  attr_accessor :ipProtocol
  attr_accessor :fromPort
  attr_accessor :toPort
  attr_accessor :groups
  attr_accessor :ipRanges
end

class QEc2_SecurityGroupItemType
  attr_accessor :groupName
  attr_accessor :groupDescription
  attr_accessor :ownerId
  attr_accessor :ipPermissions
end


class QEc2_DescribeSecurityGroupsParser < QEc2_Parser
  def tagstart(name, attributes)
    case name
      when 'item' 
        if @xmlpath=='DescribeSecurityGroupsResponse/securityGroupInfo'
          @group = QEc2_SecurityGroupItemType.new 
          @group.ipPermissions = []
        elsif @xmlpath=='DescribeSecurityGroupsResponse/securityGroupInfo/item/ipPermissions'
          @perm = QEc2_IpPermissionType.new
          @perm.ipRanges = []
          @perm.groups   = []
        elsif @xmlpath=='DescribeSecurityGroupsResponse/securityGroupInfo/item/ipPermissions/item/groups'
          @sgroup = QEc2_UserIdGroupPairType.new
        end
    end
  end
  def tagend(name)
    case name
      when 'ownerId'          ; @group.ownerId   = @text
      when 'groupDescription' ; @group.groupDescription = @text
      when 'groupName'
        if @xmlpath=='DescribeSecurityGroupsResponse/securityGroupInfo/item'
          @group.groupName  = @text 
        elsif @xmlpath=='DescribeSecurityGroupsResponse/securityGroupInfo/item/ipPermissions/item/groups/item'
          @sgroup.groupName = @text 
        end
      when 'ipProtocol'       ; @perm.ipProtocol = @text
      when 'fromPort'         ; @perm.fromPort   = @text
      when 'toPort'           ; @perm.toPort     = @text
      when 'userId'           ; @sgroup.userId   = @text
      when 'cidrIp'           ; @perm.ipRanges  << @text
      when 'item'
        if @xmlpath=='DescribeSecurityGroupsResponse/securityGroupInfo/item/ipPermissions/item/groups'
          @perm.groups << @sgroup
        elsif @xmlpath=='DescribeSecurityGroupsResponse/securityGroupInfo/item/ipPermissions'
          @group.ipPermissions << @perm
        elsif @xmlpath=='DescribeSecurityGroupsResponse/securityGroupInfo'
          @result << @group
        end
    end
  end
  def reset
    @result = []
  end
end

#-----------------------------------------------------------------
#      PARSERS: Images
#-----------------------------------------------------------------

class QEc2_DescribeImagesResponseItemType
  attr_accessor :imageId 
  attr_accessor :imageState 
  attr_accessor :imageLocation
  attr_accessor :imageOwnerId 
  attr_accessor :isPublic
end


class QEc2_DescribeImagesParser < QEc2_Parser
  def tagstart(name, attributes)
    @image = QEc2_DescribeImagesResponseItemType.new if name == 'item'
  end
  def tagend(name)
    case name
      when 'imageId'       ; @image.imageId       = @text
      when 'imageLocation' ; @image.imageLocation = @text
      when 'imageState'    ; @image.imageState    = @text
      when 'imageOwnerId'  ; @image.imageOwnerId  = @text
      when 'isPublic'      ; @image.isPublic      = @text == 'true' ? true : false
      when 'item'          ; @result << @image
    end
  end
  def reset
    @result = []
  end
end


class QEc2_RegisterImageParser < QEc2_Parser
  def tagend(name)
    @result = @text if name == 'imageId'
  end
end


#-----------------------------------------------------------------
#      PARSERS: Image Attribute
#-----------------------------------------------------------------

class QEc2_LaunchPermissionItemType
  attr_accessor :groups
  attr_accessor :userIds
end
  
class QEc2_DescribeImageAttributeType
  attr_accessor :imageId 
  attr_accessor :launchPermission
end

class QEc2_DescribeImageAttributeParser < QEc2_Parser
  def tagstart(name, attributes)
    case name
      when 'launchPermission'
        @result.launchPermission = QEc2_LaunchPermissionItemType.new
        @result.launchPermission.groups  = []
        @result.launchPermission.userIds = []
    end
  end
  def tagend(name)
      # right now only 'launchPermission' is supported by Amazon. 
      # But nobody know what will they xml later as attribute. That is why we 
      # check for 'group' and 'userId' inside of 'launchPermission/item'
    case name
      when 'imageId' ; @result.imageId = @text
      when 'group'   
        @result.launchPermission.groups  << @text if @xmlpath == 'DescribeImageAttributeResponse/launchPermission/item'
      when 'userId'  
        @result.launchPermission.userIds << @text if @xmlpath == 'DescribeImageAttributeResponse/launchPermission/item'
    end
  end
  def reset
    @result = QEc2_DescribeImageAttributeType.new 
  end
end

#-----------------------------------------------------------------
#      PARSERS: Instances
#-----------------------------------------------------------------

class QEc2_InstanceStateType
  attr_accessor :code
  attr_accessor :name
end

class QEc2_RunningInstancesItemType
  attr_accessor :instanceId
  attr_accessor :imageId
  attr_accessor :instanceState
  attr_accessor :dnsName
  attr_accessor :privateDnsName
  attr_accessor :reason
  attr_accessor :keyName
  attr_accessor :amiLaunchIndex
end

class QEc2_DescribeInstancesType
  attr_accessor :reservationId
  attr_accessor :ownerId
  attr_accessor :groupSet
  attr_accessor :instancesSet 
end

class QEc2_DescribeInstancesParser < QEc2_Parser
  def tagstart(name, attributes)
    case name
      when 'item'
        if @xmlpath=='DescribeInstancesResponse/reservationSet'
          @reservation = QEc2_DescribeInstancesType.new 
          @reservation.groupSet     = []
          @reservation.instancesSet = []
        elsif @xmlpath=='DescribeInstancesResponse/reservationSet/item/instancesSet'
          @instance = QEc2_RunningInstancesItemType.new
            # the optional params (sometimes are missing and we dont want them to be nil) 
          @instance.reason         = ''
          @instance.dnsName        = ''
          @instance.privateDnsName = ''
          @instance.amiLaunchIndex = ''
          @instance.keyName        = ''
          @instance.instanceState  = QEc2_InstanceStateType.new
       end
     end
  end
  def tagend(name)
    case name 
      when 'reservationId' ; @reservation.reservationId   = @text
      when 'ownerId'       ; @reservation.ownerId         = @text
      when 'groupId'       ; @reservation.groupSet       << @text
      when 'instanceId'    ; @instance.instanceId         = @text
      when 'imageId'       ; @instance.imageId            = @text
      when 'dnsName'       ; @instance.dnsName            = @text
      when 'privateDnsName'; @instance.privateDnsName     = @text
      when 'reason'        ; @instance.reason             = @text
      when 'keyName'       ; @instance.keyName            = @text
      when 'amiLaunchIndex'; @instance.amiLaunchIndex     = @text
      when 'code'          ; @instance.instanceState.code = @text
      when 'name'          ; @instance.instanceState.name = @text
      when 'item'
        if @xmlpath=='DescribeInstancesResponse/reservationSet/item/instancesSet'
          @reservation.instancesSet << @instance
        elsif @xmlpath=='DescribeInstancesResponse/reservationSet'
          @result << @reservation
        end
    end
  end
  def reset
    @result = []
  end
end


class QEc2_RunInstancesParser < QEc2_Parser
  def tagstart(name, attributes)
    case name
      when 'RunInstancesResponse'
        @reservation = QEc2_DescribeInstancesType.new 
        @reservation.groupSet     = []
        @reservation.instancesSet = []
      when 'item'
        if @xmlpath == 'RunInstancesResponse/instancesSet'
          @instance = QEc2_RunningInstancesItemType.new
            # the optional params (sometimes are missing and we dont want them to be nil) 
          @instance.reason         = ''
          @instance.dnsName        = ''
          @instance.privateDnsName = ''
          @instance.amiLaunchIndex = ''
          @instance.keyName        = ''
          @instance.instanceState  = QEc2_InstanceStateType.new
        end
     end
  end
  def tagend(name)
    case name 
      when 'reservationId' ; @reservation.reservationId   = @text
      when 'ownerId'       ; @reservation.ownerId         = @text
      when 'groupId'       ; @reservation.groupSet       << @text
      when 'instanceId'    ; @instance.instanceId         = @text
      when 'imageId'       ; @instance.imageId            = @text
      when 'dnsName'       ; @instance.dnsName            = @text
      when 'privateDnsName'; @instance.privateDnsName     = @text
      when 'reason'        ; @instance.reason             = @text
      when 'keyName'       ; @instance.keyName            = @text
      when 'amiLaunchIndex'; @instance.amiLaunchIndex     = @text
      when 'code'          ; @instance.instanceState.code = @text
      when 'name'          ; @instance.instanceState.name = @text
      when 'item'          
        @reservation.instancesSet << @instance if @xmlpath == 'RunInstancesResponse/instancesSet'
      when 'RunInstancesResponse'; @result << @reservation
    end
  end
  def reset
    @result = []
  end
end

class QEc2_TerminateInstancesResponseInfoType
  attr_accessor :instanceId
  attr_accessor :shutdownState
  attr_accessor :previousState
end

class QEc2_TerminateInstancesParser < QEc2_Parser
  def tagstart(name, attributes)
    if name == 'item'
      @instance = QEc2_TerminateInstancesResponseInfoType.new 
      @instance.shutdownState = QEc2_InstanceStateType.new
      @instance.previousState = QEc2_InstanceStateType.new
    end
  end
  def tagend(name)
    case name
    when 'instanceId' ; @instance.instanceId  = @text
    when 'item'       ; @result              << @instance
    when 'code'
      if @xmlpath == 'TerminateInstancesResponse/instancesSet/item/shutdownState'
           @instance.shutdownState.code = @text
      else @instance.previousState.code = @text end
    when 'name'
      if @xmlpath == 'TerminateInstancesResponse/instancesSet/item/shutdownState'
           @instance.shutdownState.name = @text
      else @instance.previousState.name = @text end
    end
  end
  def reset
    @result = []
  end
end


#-----------------------------------------------------------------
#      PARSERS: Console
#-----------------------------------------------------------------

class QEc2_GetConsoleOutputResponseType
  attr_accessor :instanceId
  attr_accessor :timestamp
  attr_accessor :output
end

class QEc2_GetConsoleOutputParser < QEc2_Parser
  def tagend(name)
    case name
    when 'instanceId' ; @result.instanceId = @text
    when 'timestamp'  ; @result.timestamp  = @text
    when 'output'     ; @result.output     = Base64.decode64 @text
    end
  end
  def reset
    @result = QEc2_GetConsoleOutputResponseType.new
  end
end