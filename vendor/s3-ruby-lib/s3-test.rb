#!/usr/bin/env ruby

# This software code is made available "AS IS" without warranties of any        
# kind.  You may copy, display, modify and redistribute the software            
# code either by itself or as incorporated into your code; provided that        
# you do not remove any proprietary notices.  Your use of this software         
# code is at your own risk and you waive any claim against Amazon               
# Digital Services, Inc. or its affiliates with respect to your use of          
# this software code. (c) 2006 Amazon Digital Services, Inc. or its             
# affiliates.          

require 'test/unit'
require 'S3'

AWS_ACCESS_KEY_ID = '18518BXJYB0KKSSCYSG2'
AWS_SECRET_ACCESS_KEY = '1olDZMLrmJlTN/9z0R1sfFZFmpAlgz3OQ5PFGDck'

BUCKET_NAME = "%s-test" % AWS_ACCESS_KEY_ID;
puts "Bucket name: #{BUCKET_NAME}"

class TC_AWSAuthConnectionTest < Test::Unit::TestCase
  def setup
    @conn = S3::AWSAuthConnection.new(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, false)
  end

  def test_operations
    response = @conn.create_bucket(BUCKET_NAME)
    assert_equal(200, response.http_response.code.to_i, 'create bucket')

    response = @conn.list_bucket(BUCKET_NAME)
    assert_equal(response.http_response.code.to_i, 200, 'list bucket')
    assert_equal(response.entries.length, 0, 'bucket is empty')

    text = 'this is a test'
    key = 'test'

    response = @conn.put(BUCKET_NAME, key, text)
    assert_equal(response.http_response.code.to_i, 200, 'put with a string argument')

    response =
      @conn.put(
        BUCKET_NAME,
        key,
        S3::S3Object.new(text, {'title' => 'title'}),
        {'Content-Type' => 'text/plain'})

    assert_equal(response.http_response.code.to_i, 200, 'put with complex argument and headers')

    response = @conn.get(BUCKET_NAME, key)
    assert_equal(response.http_response.code.to_i, 200, 'get object')
    assert_equal(response.object.data, text, 'got right data')
    assert_equal(response.object.metadata, { 'title' => 'title' }, 'metadata is correct')
    assert_equal(response.http_response['Content-Length'].to_i, text.length, 'got content-length header')


    title_with_spaces = " \t  title with leading and trailing spaces    "
    response =
      @conn.put(
        BUCKET_NAME,
        key,
        S3::S3Object.new(text, {'title' => title_with_spaces}),
        {'Content-Type' => 'text/plain'})

    assert_equal(
      response.http_response.code.to_i, 200, 'put with metadata with leading and trailing spaces')

    response = @conn.get(BUCKET_NAME, key)
    assert_equal(response.http_response.code.to_i, 200, 'get object')
    assert_equal(
      response.object.metadata,
      { 'title' => title_with_spaces.strip },
      'metadata is correct')

    weird_key = '&=//%# ++++'

    response = @conn.put(BUCKET_NAME, weird_key, text)
    assert_equal(response.http_response.code.to_i, 200, 'put weird key')

    response = @conn.get(BUCKET_NAME, weird_key)
    assert_equal(response.http_response.code.to_i, 200, 'get weird key')

    response = @conn.get_acl(BUCKET_NAME, key)
    assert_equal(response.http_response.code.to_i, 200, 'get acl')

    acl = response.object.data

    response = @conn.put_acl(BUCKET_NAME, key, acl)
    assert_equal(response.http_response.code.to_i, 200, 'put acl')

    response = @conn.get_bucket_acl(BUCKET_NAME)
    assert_equal(response.http_response.code.to_i, 200, 'get bucket acl')

    bucket_acl = response.object.data

    response = @conn.put_bucket_acl(BUCKET_NAME, bucket_acl)
    assert_equal(response.http_response.code.to_i, 200, 'put bucket acl')

    response = @conn.list_bucket(BUCKET_NAME)
    assert_equal(response.http_response.code.to_i, 200, 'list bucket')
    entries = response.entries
    assert_equal(entries.length, 2, 'got back right number of keys')
    # depends on weird_key < key
    assert_equal(entries[0].key, weird_key, 'first key is right')
    assert_equal(entries[1].key, key, 'second key is right')

    response = @conn.list_bucket(BUCKET_NAME, {'max-keys' => 1})
    assert_equal(response.http_response.code.to_i, 200, 'list bucket with args')
    assert_equal(response.entries.length, 1, 'got back right number of keys')

    entries.each do |entry|
      response = @conn.delete(BUCKET_NAME, entry.key)
      assert_equal(response.http_response.code.to_i, 204, 'delete %s' % entry.key)
    end

    response = @conn.list_all_my_buckets()
    assert_equal(response.http_response.code.to_i, 200, 'list all my buckets')
    buckets = response.entries

    response = @conn.delete_bucket(BUCKET_NAME)
    assert_equal(response.http_response.code.to_i, 204, 'delete bucket')

    response = @conn.list_all_my_buckets()
    assert_equal(response.http_response.code.to_i, 200, 'list all my buckets again')

    assert_equal(response.entries.length, buckets.length - 1, 'bucket count is correct')
  end
end

class TC_QueryStringAuthGeneratorTest < Test::Unit::TestCase
  def setup
    @generator = S3::QueryStringAuthGenerator.new(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, false)
    @http = Net::HTTP.new(@generator.server, @generator.port)
    @put_headers = { 'Content-Type' => 'text/plain' }
  end

  def method_to_request_class(method)
    case method
    when 'GET'
      return Net::HTTP::Get
    when 'PUT'
      return Net::HTTP::Put
    when 'DELETE'
      return Net::HTTP::Delete
    else
      raise "Unsupported method #{method}"
    end
  end

  def check_url(url, method, code, message, data='', headers={})
    @http.start do
      uri = URI.parse(url)
      req = method_to_request_class(method).new(uri.request_uri)
      if (method == 'PUT')
        #req['Content-Length'] = "12"
        #puts req['Content-Length'].inspect
        #puts data.length
        #puts data.inspect
        req['Content-Length'] = "#{data.length}"
        @put_headers.each do |header, value|
          req[header] = value
        end
        response = @http.request(req, data)
      else
        response = @http.request(req)
      end
      assert_equal(code, response.code.to_i, message)
      return response.body
    end
  end

  def test_operations
   key = 'test'
    check_url(@generator.create_bucket(BUCKET_NAME, @put_headers), 'PUT', 200, 'create_bucket')
    check_url(@generator.put(BUCKET_NAME, key, '', @put_headers), 'PUT', 200, 'put object', 'test data')
    check_url(@generator.get(BUCKET_NAME, key), 'GET', 200, 'get object')
    check_url(@generator.list_bucket(BUCKET_NAME), 'GET', 200, 'list bucket')
    check_url(@generator.list_all_my_buckets(), 'GET', 200, 'list all my buckets')
    acl = check_url(@generator.get_acl(BUCKET_NAME, key), 'GET', 200, 'get acl')
    check_url(@generator.put_acl(BUCKET_NAME, key, acl, @put_headers), 'PUT', 200, 'put acl', acl)
    bucket_acl = check_url(@generator.get_bucket_acl(BUCKET_NAME), 'GET', 200, 'get bucket acl')
    check_url(@generator.put_bucket_acl(BUCKET_NAME, bucket_acl, @put_headers), 'PUT', 200, 'put bucket acl', bucket_acl)
    check_url(@generator.delete(BUCKET_NAME, key), 'DELETE', 204, 'delete object')
    check_url(@generator.delete_bucket(BUCKET_NAME), 'DELETE', 204, 'delete bucket')
  end
end
