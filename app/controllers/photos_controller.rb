require 'right_aws'
#require 'lib/ec2/sqs_query'
require 's3-ruby-lib/S3'
#require 'ruby-debug'

PATH_TO_PHOTOS   = 'public/images/photos'
URL_TO_PHOTOS    = '/photos'
PHOTOS_BUCKET    = 'photo_demo_bucket'
PHOTOS_IN_KEY    = 'in'
PHOTO_QUEUE_NAME = 'Photo-Demo-In'

MAX_NUM_PHOTOS          = 50
MAX_NUM_TRANSFORMATIONS = 10

@@orders_photos = []

class PhotosController < ApplicationController
  
  @photos = `dir #{PATH_TO_PHOTOS}/small`.split.map{|file| file[/.*jpg/]}.compact

  session :off, :only => :health_check
  
  def index
    form        = params[:form]
    @num_orders = form[:num_orders].to_i  if form
    @num_photos = form[:num_photos].to_i  if form
  end
  
  def health_check
  end
  
  def create_orders
    form        = params[:form]
    @num_orders = form[:num_orders].to_i
    @num_photos = form[:num_photos].to_i
    # @num_transf = form[:transformations].to_i
    
    @orders_photos = get_randomize_arrays(@num_orders, @num_photos, MAX_NUM_PHOTOS)

    new_orders = []
    @orders_photos.each do |order|
      new_order = []
      order.each do |elem|
        new_order << "image_" + elem.to_s + ".jpg"
      end
      new_orders << new_order.dup
    end    
    
    @orders = new_orders.dup
  end

  def submit_orders
    form        = params[:form]
    @orders     = YAML::load(form[:orders])
    @num_orders = form[:num_orders].to_i
    @num_photos = form[:num_photos].to_i

    @message_to_render = ""
    
    i = 1
    @orders.each do |photos|
      photos.map!{ |photo| "#{PHOTOS_BUCKET}/#{PHOTOS_IN_KEY}/#{photo}" }

      message = { 'submit_time' => Time.now.utc.strftime('%Y-%m-%d %H:%M:%S'),
                  's3_download' => photos,
                  'worker_name' => 'RightPhotoWorker'
                }
              
      sqs   = RightAws::SqsGen2.new(AWS_ACCESS_KEY, AWS_SECRET_KEY)
      queue = sqs.queue(PHOTO_QUEUE_NAME)
    
      message_yaml = YAML.dump(message)
      message_id   = queue.send_message(message_yaml)
      
      message_id = 0 if ! message_id
    
      message_out = message.select { |k, v| k != "s3_download" }
      
      @message_to_render +=
            "<fieldset><legend><em>Order " + i.to_s + ":</em></legend>" +
            "Message ID => " + message_id.to_s + "</fieldset>"
            
      i += 1
    end
  end

  def upload_photos
    s3     = S3::AWSAuthConnection.new(AWS_ACCESS_KEY, AWS_SECRET_KEY)
    photos = `dir #{PATH_TO_PHOTOS}/mine_big`.split.map{|file| file[/.*jpg/]}.compact
    s3_upload_all(s3, PATH_TO_PHOTOS+'/mine_big', photos, PHOTOS_BUCKET, PHOTOS_IN_KEY)
    render :text => "Uploaded " + photos.size.to_s + " files; done!"
  end

  private
    
  def get_randomize_arrays (num_arrays, elems_per_array, total_elems)
    upper   = total_elems
    lower   = upper - elems_per_array + 1
    
    elems  = (1..total_elems).to_a
    arrays = []
    
    1.upto(num_arrays) do 
      rand_array = []
      upper.downto(lower) do |range|
        rpos = (range * rand).to_i
        rand_array << elems[rpos]
        elems[rpos]    = elems[range-1]
        elems[range-1] = rand_array.last
      end
      arrays << rand_array
    end
    
    arrays
  end
  
  def s3_upload_all(s3, path, list, bucket, key)
    list.each do |file|
      File.open("#{path}/#{file}", 'r'){ |dfile| 
        puts "uploading '#{file}' to '#{bucket}/#{key}'"
        s3.put(bucket, key+"/#{file}", dfile.read) 
      }
    end
  end

end
