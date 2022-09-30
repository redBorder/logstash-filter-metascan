# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

require 'json'
require 'faraday'
require 'digest'
require 'aerospike'

require_relative "util/aerospike_config"
require_relative "util/aerospike_manager"
require_relative "util/s3_manager"

class LogStash::Filters::Metascan < LogStash::Filters::Base

  include Aerospike

  config_name "metascan"

  # Metascan apikey. Please visit https://metadefender.opswat.com/account to get your apikey.
  config :apikey,                           :validate => :string,           :default => "",       :required => true
  # File that is going to be analyzed
  config :file_field,                       :validate => :string,           :default => "[path]"
  # Timeout waiting for response
  config :timeout,                          :validate => :number,           :default => 15
  # Where you want the data to be placed
  config :target,                           :validate => :string,           :default => "metascan"
  # Where you want the score to be placed
  config :score_name,                       :validate => :string,           :default => "fb_metascan"
  # Where you want the latency to be placed
  config :latency_name,                     :validate => :string,           :default => "metascan_latency"
  # Aerospike server in the form "host:port"
  config :aerospike_server,                 :validate => :string,           :default => ""
  # Namespace is a Database name in Aerospike
  config :aerospike_namespace,              :validate => :string,           :default => "malware"
  # Set in Aerospike is similar to table in a relational database.
  # Where are scores stored
  config :aerospike_set,                    :validate => :string,           :default => "hashScores"
  # Where you want to store the results in s3
  config :s3_path,                          :validate => :string,           :default => "/mdata/resultData/realTime/"
  # S3 bucket
  config :bucket,                           :validate => :string,           :default => "malware"
  # S3 Endpoint
  config :endpoint,                         :validate => :string,           :default => "s3.redborder.cluster"
  # S3 Access key
  config :access_key_id,                    :validate => :string,           :default => ""
  # S3 Secret Access key
  config :secret_access_key,                :validate => :string,           :default => ""
  # S3 force_path_style option
  config :force_path_style,                 :validate => :boolean,          :default => true
  # S3 ssl_verify_peer option
  config :ssl_verify_peer,                  :validate => :boolean,          :default => false
  # Certificate path
  config :ssl_ca_bundle,                    :validate => :string,           :default => "/var/opt/opscode/nginx/ca/s3.redborder.cluster.crt"


  public
  def register
    # Add instance variables
    @url_hash = "https://api.metadefender.com/v4/hash/"
    @url_file = "https://api.metadefender.com/v4/file"

    begin
      @aerospike_server = AerospikeConfig::servers if @aerospike_server.empty?
      @aerospike_server = @aerospike_server[0] if @aerospike_server.class.to_s == "Array"
      host,port = @aerospike_server.split(":")
      @aerospike = Client.new(Host.new(host, port))

    rescue Aerospike::Exceptions::Aerospike => ex
      @logger.error(ex.message)
    end

  end # def register

  private

  def check_response(response)
    response_code = response.status

    case response_code
      when 200
        response_message = ""
      when 400
        response_message = "CODE 400 Bad Request - Unsupported HTTP method or invalid HTTP request (e.g., empty body)"
      when 401
        response_message = "CODE 401 Invalid API key - Either missing API key or invalid API is passed."
      when 403
        response_message = "CODE 403 Signature lookup limit reached, try again later - The hourly hash lookup limit has been reached for this API key."
      when 404
        response_message = "CODE 404 The requested page was not found. Try to upload the file."
      when 429
        response_message = "CODE 429 Rate limit exceeded, retry after the limit is reset."
      when 503
        response_message = "CODE 503 Internal Server Error - Server temporarily unavailable. Try again later."
      else
        response_message = "Unexpected error"
    end

    [response_code,response_message]
  end

  def get_response_from_hash
    connection = Faraday.new @url_hash
    score = -1
    result = {}

    begin
      response = connection.get @hash do |req|
        req.headers[:apikey] = @apikey
        req.options.timeout = @timeout
        req.options.open_timeout = @timeout
      end

      response_code,response_message = check_response(response)
      if response_code != 200
        @logger.error(response_message)
        return [result, score]
      end

      result = JSON.parse(response.body)
      unless result["error"]
        total_avs = result["scan_results"]["total_avs"].to_f
        total_detected_avs = result["scan_results"]["total_detected_avs"].to_f
        score = ( total_detected_avs / total_avs * 100 ).round
      end

    rescue Faraday::TimeoutError
      @logger.error("Timeout trying to contact Metascan")

    rescue Faraday::ConnectionFailed => ex
      @logger.error(ex.message)
    end
    [result, score]
  end

  def send_file
    connection = Faraday.new @url_file
    data_id = nil
    begin
      response = connection.post do |req|
        req.headers[:apikey] = @apikey
        req.headers["Content-Type"] = "application/octet-stream"
        req.options.timeout = @timeout
        req.options.open_timeout = @timeout
        req.body = "{ \"data\" : #{@path}}"
      end

      response_code,response_message = check_response(response)
      if response_code != 200
        @logger.error(response_message)
        return [result, score]
      end

      data_id = JSON.parse(response.body)["data_id"]

    rescue Faraday::TimeoutError
      @logger.error("Timeout trying to contact Metascan")
    end
    data_id
  end

  def get_response_from_data_id(data_id)
    connection = Faraday.new @url_file + "/"
    progress_percentage = 0
    score = -1
    result = {}
    begin

      while progress_percentage < 100
        response = connection.get data_id do |req|
          req.headers[:apikey] = @apikey
          req.headers["x-file-metadata"] = "1"
          req.options.timeout = @timeout
          req.options.open_timeout = @timeout
        end

        response_code,response_message = check_response(response)
        if response_code != 200
          @logger.error(response_message)
          return [result, score]
        end

        result = JSON.parse(response.body)
        progress_percentage = result["scan_results"]["progress_percentage"]
      end

    rescue Faraday::TimeoutError
      @logger.error("Timeout trying to contact Metascan")
    rescue Faraday::ConnectionFailed => ex
      @logger.error(ex.message)
    end

    total_avs = result["scan_results"]["total_avs"].to_f
    total_detected_avs = result["scan_results"]["total_detected_avs"].to_f

    score = ( total_detected_avs / total_avs * 100 ).round

    [result, score]
  end


  public
  def filter(event)
    @path = event.get(@file_field)
    @logger.info "[metscan] processing #{@path}"
    @timestamp = event.get('@timestamp')
    begin
      @hash = Digest::SHA2.new(256).hexdigest File.read @path
    rescue Errno::ENOENT => ex
      @logger.error(ex.message)
    end


    starting_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    metascan_result,score = get_response_from_hash

    # The hash was not found. Error code 404003
    if metascan_result.empty?
      data_id = send_file
      metascan_result,score = get_response_from_data_id(data_id)
    end

    ending_time  = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    elapsed_time = (ending_time - starting_time).round(1)

    event.set(@latency_name, elapsed_time)
    event.set(@target, metascan_result)
    event.set(@score_name, score)

    AerospikeManager::update_malware_hash_score(@aerospike, @aerospike_namespace, @aerospike_set, @hash, @score_name, score, "fb")

    if !@access_key_id.empty? and !@secret_access_key.empty?
      S3Manager::update_results_file_s3(metascan_result, File.basename(@path), @timestamp,
                                        @target, @s3_path, @bucket, @endpoint, @access_key_id,
                                        @secret_access_key, @force_path_style, @ssl_verify_peer, @ssl_ca_bundle, @logger)
    end
    # filter_matched should go in the last line of our successful code
    filter_matched(event)

  end  # def filter(event)
end # class LogStash::Filters::Metascan
