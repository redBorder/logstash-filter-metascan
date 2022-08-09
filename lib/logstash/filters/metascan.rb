# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

require 'json'
require 'faraday'
require 'digest'


class LogStash::Filters::Metascan < LogStash::Filters::Base

  config_name "metascan"

  # Metascan apikey. Please visit https://metadefender.opswat.com/account to get your apikey.
  config :apikey,      :validate => :string,  :default => "",  :required => true
  # File that is going to be analyzed
  config :file_field,   :validate => :string,  :default => "[path]"
  # Timeout waiting for response
  config :timeout, :validate => :number, :default => 15
  # Loader weight
  config :weight, :default => 1.0
  # Where you want the data to be placed
  config :target, :validate => :string, :default => "metascan"
  # Where you want the score to be placed
  config :score_name, :validate => :string, :default => "fb_metascan"
  # Where you want the latency to be placed
  config :latency_name, :validate => :string, :default => "metascan_latency"


  public
  def register
    # Add instance variables
    @url_hash = "https://api.metadefender.com/v4/hash/"
    @url_file = "https://api.metadefender.com/v4/file"
  end # def register

  private

  def check_response(response)
    response_code = response.status

    case response_code
      when 400
        response_message = "CODE 400 Bad Request - Unsupported HTTP method or invalid HTTP request (e.g., empty body)"
      when 401
        response_message = "CODE 401 Invalid API key - Either missing API key or invalid API is passed."
      when 403
        response_message = "CODE 403 Signature lookup limit reached, try again later - The hourly hash lookup limit has been reached for this API key."
      when 404
        response_message = "CODE 404 The requested page was not found. Try to upload the file."
      when 503
        response_message = "CODE 503 Internal Server Error - Server temporarily unavailable. Try again later."
      else #when 200
      response_message = ""
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
        return [score,result]
      end

      result = JSON.parse(response.body)
      unless result["error"]
        total_avs = result["scan_results"]["total_avs"].to_f
        total_detected_avs = result["scan_results"]["total_detected_avs"].to_f
        score = ( (total_detected_avs / total_avs * 100) * @weight ).round
      end

    rescue Faraday::TimeoutError
      @logger.error("Timeout trying to contact Metascan")

    rescue Faraday::ConnectionFailed => ex
      puts ex.message
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
        return [score,result]
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
          return [score,result]
        end

        result = JSON.parse(response.body)
        progress_percentage = result["scan_results"]["progress_percentage"]
      end

    rescue Faraday::TimeoutError
      @logger.error("Timeout trying to contact Metascan")
    rescue Faraday::ConnectionFailed => ex
      puts ex.message
    end

    total_avs = result["scan_results"]["total_avs"].to_f
    total_detected_avs = result["scan_results"]["total_detected_avs"].to_f

    score = ( (total_detected_avs / total_avs * 100) * @weight ).round

    [result, score]
  end


  public
  def filter(event)

    @path = event.get(@file_field)
    begin
      @hash = Digest::MD5.hexdigest File.read @path
    rescue Errno::ENOENT => ex
      @logger.error(ex.message)
    end


    starting_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    metascan_result,score = get_response_from_hash

    # The hash was not found. Error code 404003
    if metascan_result["error"]
      data_id = send_file
      metascan_result,score = get_response_from_data_id(data_id)
    end

    ending_time  = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    elapsed_time = (ending_time - starting_time).round(1)

    event.set(@latency_name, elapsed_time)
    event.set(@target, metascan_result)
    event.set(@score_name, score)
    # filter_matched should go in the last line of our successful code
    filter_matched(event)

  end  # def filter(event)
end # class LogStash::Filters::Metascan
