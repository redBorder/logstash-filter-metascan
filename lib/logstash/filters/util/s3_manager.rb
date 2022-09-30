require 'aws-sdk'

module S3Manager

  def self.update_results_file_s3(json,uuid,timestamp, loader, s3_path, bucket,
                                  endpoint, access_key_id,secret_access_key,
                                  force_path_style,ssl_verify_peer,ssl_ca_bundle)

    #s3 = Aws::S3::Client.new(    #Gem 2.0
    s3 = AWS::S3::Client.new(
      endpoint: endpoint,
      access_key_id: access_key_id,
      secret_access_key: secret_access_key,
      force_path_style:  force_path_style,
      ssl_verify_peer: ssl_verify_peer,
      ssl_ca_bundle: ssl_ca_bundle
    #region: 'us-east-1'          #Gem 2.0
    )

    results = []

    time = Time.at(timestamp.to_i)

    folder = time.year.to_s + "/" + time.month.to_s + "/" +
             time.day.to_s  + "/" + time.hour.to_s  + "/" + uuid

    s3_result_path = s3_path + folder

    begin
      # results = eval(s3.get_object(bucket: bucket, key: s3_result_path).data[:data]) #Gem 2.0
      results = eval(s3.get_object(bucket_name: bucket, key: s3_result_path).data[:data])
      results = [] if results.nil?
    rescue AWS::S3::Errors::NoSuchKey
      results = []
    rescue => e #AWS::Errors::ServiceError => e  #Gem 2.0
      #@logger.error(e.message)
      puts e.message
    end

    json["loader"] = loader

    results.push(JSON.pretty_generate(json))

    # Writing temporary file
    File.open('/tmp/' + uuid, 'w',) do |f|
      File.chmod(0777,'/tmp/' + uuid)
      FileUtils.chown 'logstash', 'logstash', '/tmp/' + uuid

      f.puts results
    end

    begin
    # Uploading file to s3
      open('/tmp/' + uuid, 'r') do |f|
        # s3.put_object(bucket: bucket, key: s3_result_path, body: f)       #Gem 2.0
        s3.put_object(bucket_name: bucket, key: s3_result_path, data: f)  #Gem 1.61.0
      end
    rescue => e #AWS::Errors::ServiceError => e  #Gem 2.0
      @logger.error(e.message)
    end

    # Deleting temporary file
    open('/tmp/' + uuid, 'w') do |f|
      File.delete(f)
    end

  end
end
