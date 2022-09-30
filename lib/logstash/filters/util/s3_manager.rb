require 'aws-sdk-v1'

module S3Manager

  def self.update_results_file_s3(json,uuid,timestamp, loader, s3_path, bucket,
                                  endpoint, access_key_id,secret_access_key,
                                  force_path_style,ssl_verify_peer,ssl_ca_bundle)

    s3 = AWS::S3::Client.new(
      endpoint: endpoint,
      access_key_id: access_key_id,
      secret_access_key: secret_access_key,
      force_path_style:  force_path_style,
      ssl_verify_peer: ssl_verify_peer,
      ssl_ca_bundle: ssl_ca_bundle
    )

    results = []

    time = Time.at(timestamp.to_i)

    year  = time.year.to_s
    month = ('%02d' % time.month).to_s
    day   = ('%02d' % time.day).to_s
    hour  = ('%02d' % time.hour).to_s

    folder = year + "/" + month + "/" + day  + "/" + hour  + "/" + uuid

    s3_result_path = s3_path + folder

    temporary_file_path = '/tmp/' + uuid

    begin
      results = eval(s3.get_object(bucket_name: bucket, key: s3_result_path).data[:data])
      results = [] if results.nil?
    rescue AWS::S3::Errors::NoSuchKey
      results = []
    rescue => e
      @logger.error(e.message)
    end

    json["loader"] = loader

    results.push(JSON.pretty_generate(json))

    # Writing temporary file
    File.open(temporary_file_path, 'w',) do |f|
      File.chmod(0777,'/tmp/' + uuid)
      FileUtils.chown 'logstash', 'logstash', temporary_file_path
      f.puts results
    end

    begin
    # Uploading file to s3
      @logger.info("Uploading file to s3")
      open(temporary_file_path, 'r') do |f|
        s3.put_object(bucket_name: bucket, key: s3_result_path, data: f)
      end
    rescue => e
      @logger.error(e.message)
    end

    # Deleting temporary file
    open(temporary_file_path, 'w') do |f|
      File.delete(f)
    end
  end
end
