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


  public
  def register
    # Add instance variables
    @url_hash = "https://api.metadefender.com/v4/hash/"
    @url_file = "https://api.metadefender.com/v4/file"
  end # def register

  private
  def get_response_from_hash
    connection = Faraday.new @url_hash
    score = nil
    result = nil

    begin
      response = connection.get @hash do |req|
        req.headers[:apikey] = @apikey
        req.options.timeout = @timeout
        req.options.open_timeout = @timeout
      end

      result = JSON.parse(response.body)

      unless result["error"]
        total_avs = result["scan_results"]["total_avs"].to_f
        total_detected_avs = result["scan_results"]["total_detected_avs"].to_f

        score = ( (total_detected_avs / total_avs * 100) * @weight ).round
      end

    rescue Faraday::TimeoutError
      @logger.error("Timeout trying to contact Metascan")
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

      data_id = JSON.parse(response.body)["data_id"]

    rescue Faraday::TimeoutError
      @logger.error("Timeout trying to contact Metascan")
    end
    data_id
  end

  def get_response_from_data_id(data_id)
    connection = Faraday.new @url_file + "/"
    progress_percentage = 0
    result = []

    while progress_percentage < 100
      begin
        response = connection.get data_id do |req|
          req.headers[:apikey] = @apikey
          req.headers["x-file-metadata"] = "1"
          req.options.timeout = @timeout
          req.options.open_timeout = @timeout
        end

        result = JSON.parse(response.body)

        progress_percentage = result["scan_results"]["progress_percentage"]

      rescue Faraday::TimeoutError
        @logger.error("Timeout trying to contact Metascan")
      end
    end

    total_avs = result["scan_results"]["total_avs"].to_f
    total_detected_avs = result["scan_results"]["total_detected_avs"].to_f

    score = ( (total_detected_avs / total_avs * 100) * @weight ).round

    [result, score]
  end


  public
  def filter(event)

    @path = event.get(@file_field)
    @hash = Digest::MD5.hexdigest File.read @path

    starting_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    metascan_result,score = get_response_from_hash

    # The hash was not found. Error code 404003
    if metascan_result["error"]
      data_id = send_file
      metascan_result,score = get_response_from_data_id(data_id)
    end

    ending_time  = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    elapsed_time = (ending_time - starting_time).round(1)

    event.set("metascan_latency", elapsed_time)
    event.set(@target, metascan_result)
    event.set(@score_name, score)
    # filter_matched should go in the last line of our successful code
    filter_matched(event)

  end  # def filter(event)
end # class LogStash::Filters::Metascan
