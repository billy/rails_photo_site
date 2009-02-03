require 'lib/ec2/ec2_query_native'
#require "./ec2_query_native"


class Ec2Query
  
  def on_query_exception(comment='', options={:raise=>true, :log=>true})
    exc        = $!
   #logger.debug("Ec2Query on_query_exception: #{exc.inspect}\n#{$@")
    comment    = " in #{comment}" unless comment.empty?
    stack      = $@[1..-1].join("\n")
    exc_str    =  exc.respond_to?('errors_str') ? exc.errors_str : exc.inspect
    error_text = "Ec2 query exception#{comment}: '#{exc_str}' at:#{$@[0]}, stack:'#{stack}'"

    # Only log & notify if not user error
    if !options[:raise] || self.system_error?(exc)
      puts         error_text if options[:puts]
      # Log the error
      if options[:log]
        logger.error error_text 
        logger.error "Request was: #{@ec2.last_request}"
        logger.error "Response was: #{@ec2.last_response || '-none-'}"
      end
    end

    # Re-raise an exception
    if options[:raise]
      if exc.is_a?(Ec2Error)
        raise Ec2Error.new("EC2 Query error(s)", exc.http_code, exc.errors, exc.requestID)
      else
        raise
      end
    end

    return nil
  end
  
  def system_error?(exc)
    !exc.is_a?(Ec2Error) || exc.errors_str =~ /InternalError|InsufficientInstanceCapacity|Unavailable/
  end

=begin

        #===== Client Error Codes ====
        
AuthFailure
InvalidManifest
InvalidAMIID.Malformed
InvalidAMIID.NotFound
InvalidAMIID.Unavailable
InvalidInstanceID.Malformed
InvalidInstanceID.NotFound
InvalidKeyPair.NotFound
InvalidKeyPair.Duplicate
InvalidGroup.NotFound
InvalidGroup.Duplicate
InvalidGroup.InUse
InvalidGroup.Reserved
InvalidPermission.Duplicate
InvalidPermission.Malformed
InvalidReservationID.Malformed
InvalidReservationID.NotFound
InstanceLimitExceeded
InvalidParameterCombination
InvalidUserID.Malformed
InvalidAMIAttributeItemValue

        #===== Server Error Codes ====
        
InternalError
InsufficientInstanceCapacity
Unavailable

=end



#  def on_query_exception(comment='', options={:raise=>true, :log=>true})
#    self.class.on_query_exception(comment,options)
#  end;

  # Use the Rails default logger
  def self.logger; return defined?(BACKGROUNDRB_LOGGER) ? BACKGROUNDRB_LOGGER : RAILS_DEFAULT_LOGGER; end
  def logger; self.class.logger; end

  #====== INIT =====
  
  def initialize(aws_access_key_id, aws_secret_access_key)
    @ec2 = Ec2_NativeQuery.new(aws_access_key_id, aws_secret_access_key)
  end
  

  #====== IMAGES =====


  def describe_images(list=[])
    images = list.nil? ? @ec2.describe_images_by_executable_by(['self']) \
                       : @ec2.describe_images_by_id(list)
    images.collect! do |image|
                  {:aws_id        => image.imageId,
                   :aws_location  => image.imageLocation,
                   :aws_owner     => image.imageOwnerId,
                   :aws_state     => image.imageState.downcase,
                   :aws_is_public => image.isPublic }
    end
  rescue Exception
    on_query_exception('describe_images')
  end
   
  def register_image(image_path)
    @ec2.register_image(image_path)
  rescue Exception
    on_query_exception('register_image')
  end
  
  def deregister_image(image_id)
    @ec2.deregister_image(image_id)
  rescue Exception
    on_query_exception('deregister_image')
  end


    #====== IMAGE ATTRIBUTES =====


    # Specifies the attribute to describe. Currently, only launchPermission is supported.
  def describe_image_attribute(image_id, attribute='launchPermission')
    image_attr = @ec2.describe_image_attribute(image_id, attribute)
    { :users  => image_attr.launchPermission.userIds,
      :groups => image_attr.launchPermission.groups }
    
  rescue Exception
    on_query_exception('describe_image_attribute')
  end
  
    # Specifies the attribute to describe. Currently, only launchPermission is supported.
  def reset_image_attribute(image_id, attribute='launchPermission')
    @ec2.reset_image_attribute(image_id, attribute)
  rescue Exception
    on_query_exception('reset_image_attribute')
  end

    # Please, use modify_image_launch_perm_add|remove_users|groups() instead of modify_image_attribute() becouse
    # they can add some attributes later and modify_image_attribute params count and types
    # will be changed. And you will need to change all your code that used modify_image_attribute.
    #
    #  attribute     : currently, only 'launchPermission' is supported.
    #  operationType : currently, only 'add' & 'remove' are supported.
    #  userGroup     : currently, only 'all' is supported.
  def modify_image_attribute(image_id, attribute, operationType, userId=[], userGroup=[])
    userId    = [userId]    if !userId.is_a? Array 
    userGroup = [userGroup] if !userGroup.is_a? Array
    @ec2.modify_image_attribute(image_id, attribute, operationType, userId, userGroup)
  rescue Exception
    on_query_exception('modify_image_attribute')
  end

  def modify_image_launch_perm_add_users(image_id, userId=[])
    modify_image_attribute(image_id, 'launchPermission',    'add', userId, [])
  end

  def modify_image_launch_perm_remove_users(image_id, userId=[])
    modify_image_attribute(image_id, 'launchPermission', 'remove', userId, [])
  end

  def modify_image_launch_perm_add_groups(image_id, userGroup=[])
    modify_image_attribute(image_id, 'launchPermission',    'add', [], userGroup)
  end
  
  def modify_image_launch_perm_remove_groups(image_id, userGroup=[])
    modify_image_attribute(image_id, 'launchPermission', 'remove', [], userGroup)
  end


  #====== INSTANCES =====

  
  def get_desc_instances(instances)
    result = []
    instances.each do |item|
      item.instancesSet.each do |instance|
        # parse and remove timestamp from the reason string: the timestamp is of
        # the request, not when EC2 took action, thus confusing & useless...
        reason = instance.reason.sub(/\(\d[^)]*GMT\) */, '')
        result << {:aws_owner          => item.ownerId,
                   :aws_reservation_id => item.reservationId,
                   :aws_groups         => item.groupSet,
                   :aws_state_code     => instance.instanceState.code,
                   :dns_name           => instance.dnsName,
                   :private_dns_name   => instance.privateDnsName,
                   :aws_instance_id    => instance.instanceId,
                   :aws_state          => instance.instanceState.name,
                   :ssh_key_name       => instance.keyName,
                   :aws_image_id       => instance.imageId,
                   :aws_reason         => reason}
      end
    end
    result
  rescue Exception
    on_query_exception('get_desc_instances')
  end
  
  def describe_instances(list=[])
    get_desc_instances(@ec2.describe_instances(list))
  rescue Exception
    on_query_exception('describe_instances')
  end
  
  def run_instances(image_id, min_count, max_count, group_ids, key_name, user_data='', addressing_type=EC2_DEFAULT_ADDRESSING_TYPE)
    logger.info("Launching instance of image #{image_id} for #{@ec2.aws_access_key_id}, key: #{key_name}, groups: #{(group_ids||[]).join(',')}")
    instances = @ec2.run_instances(image_id, min_count, max_count, key_name, group_ids, user_data, addressing_type)
    #debugger
    get_desc_instances(instances)
  rescue Exception
    on_query_exception('run_instances')
  end
  
  def terminate_instances(list=[])
    @ec2.terminate_instances(list).collect! do |instance|
            { :aws_instance_id         => instance.instanceId,
              :aws_shutdown_state      => instance.shutdownState.name,
              :aws_shutdown_state_code => instance.shutdownState.code.to_i,
              :aws_prev_state          => instance.previousState.name,
              :aws_prev_state_code     => instance.previousState.code.to_i }
    end 
  rescue Exception
    on_query_exception('terminate_instances')
  end

  def get_console_output(instanceId)
    result = @ec2.get_console_output(instanceId)
    { :aws_instance_id => result.instanceId,
      :aws_timestamp   => result.timestamp,
      :timestamp       => (Time.parse(result.timestamp)).utc,
      :aws_output      => result.output }
  rescue Exception
    on_query_exception('get_console_output')
  end

  def reboot_instances(list)
    @ec2.reboot_instances(list.to_a)
  rescue Exception
    on_query_exception('reboot_instances')
  end

 
  #====== SECURITY GROUPS =====

  
  def describe_security_groups(list=[])
    result = []     
    @ec2.describe_security_groups(list).each do |item|
      perms = []
      item.ipPermissions.each do |perm|
        perm.groups.each do |ngroup|
          perms << {:group => ngroup.groupName,
                    :owner => ngroup.userId}
        end
        perm.ipRanges.each do |cidr_ip|
          perms << {:from_port => perm.fromPort, 
                    :to_port   => perm.toPort, 
                    :protocol  => perm.ipProtocol,
                    :cidr_ips  => cidr_ip}
        end
      end
      
         # delete duplication
      perms.each_index do |i|
        (0...i).each do |j|
          if perms[i] == perms[j] then perms[i] = nil; break; end
        end
      end
      perms.compact!

      result << {:aws_owner       => item.ownerId, 
                 :aws_group_name  => item.groupName, 
                 :aws_description => item.groupDescription,
                 :aws_perms       => perms}
    end  
    return result
  rescue Exception
    on_query_exception('describe_security_groups')
  end
  
  def create_security_group(name, description)
    @ec2.create_security_group(name, description)
  rescue Exception
    on_query_exception('create_security_group')
  end
  
  def delete_security_group(name)
    @ec2.delete_security_group(name)
  rescue Exception
    on_query_exception('delete_security_group')
  end
  
  def authorize_security_group_named_ingress(name, owner, group)
    @ec2.autorize_security_group_ingress_named(name, group, owner)
  rescue Exception
    on_query_exception('authorize_security_group_named_ingress')
  end
  
  def revoke_security_group_named_ingress(name, owner, group)
    @ec2.revoke_security_group_ingress_named(name, group, owner)
  rescue Exception
    on_query_exception('revoke_security_group_named_ingress')
  end
  
    # owner is not used
  def authorize_security_group_IP_ingress(name, owner, from_port, to_port, protocol='tcp', cidr_ip='0.0.0.0/0')
    @ec2.autorize_security_group_ingress_IP(name, protocol, from_port, to_port, cidr_ip)  
  rescue Exception
    on_query_exception('authorize_security_group_IP_ingress')
  end
  
    # owner is not used
  def revoke_security_group_IP_ingress(name, owner, from_port, to_port, protocol='tcp', cidr_ip='0.0.0.0/0')
    @ec2.revoke_security_group_ingress_IP(name, protocol, from_port, to_port, cidr_ip)  
  rescue Exception
    on_query_exception('revoke_security_group_IP_ingress')
  end

  
  #====== SSH Key pairs =====


  def describe_key_pairs(list=[])
    @ec2.describe_key_pairs(list).collect! do |key|
        {:aws_key_name    => key.keyName,
         :aws_fingerprint => key.keyFingerprint }
    end
  rescue Exception
    on_query_exception('describe_key_pairs')
  end
  
  def create_key_pair(name)
    key = @ec2.create_key_pair(name)
    { :aws_key_name    => key.keyName,
      :aws_fingerprint => key.keyFingerprint,
      :aws_material    => key.keyMaterial}
  rescue Exception
    on_query_exception('create_key_pair')
  end
  
  def delete_key_pair(name)
    @ec2.delete_key_pair(name)
  rescue Exception
    on_query_exception('delete_key_pair')
  end
  
end


