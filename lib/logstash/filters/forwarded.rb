# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "ipaddr"

# The forwarded filter extracts the client ip from a list of ip adresses. The client ip might be at any position in the list, since not every x-forwarded-for header comes in the correct ordering.
# It adds two new fields to the event:
#  - forwarded_client_ip : string
#  - forwarded_proxy_list : string[]

class LogStash::Filters::Forwarded < LogStash::Filters::Base
  config_name "forwarded"
  
  # The field containing the x-forwarded-for string
  config :source, :validate => :string, :required => true

  # list of ip patterns that private ips start with. 
  config :private_ipv4_prefixes, :validate => :array, :required => false, :default => ["10.0.0.0/8", "192.168.0.0/16" ,"172.16.0.0/12"]

  # Private IP Addresses have the following ranges:
  # 10.0.0.0    - 10.255.255.255
  # 172.16.0.0  - 172.31.255.255
  # 192.168.0.0 - 192.168.255.255 

  # The name of the new field containing client ip (optional)
  config :target_client_ip, :validate => :string, :required => false, :default => "forwarded_client_ip"

  # The name of the new field containing proxy list (optional)
  config :target_proxy_list, :validate => :string, :required => false, :default => "forwarded_proxy_list"
  
  public
  def register    
    @private_ipv4_ranges = @private_ipv4_prefixes.collect do | adress |
      begin
        IPAddr.new(adress)
      rescue ArgumentError => e
        @logger.error("Register: invalid IP network, skipping", :adress => adress, :exception => e)
        raise e
       end
    end
    @private_ipv4_ranges.compact!
  end # def register

  public
  def filter(event)
    return unless filter?(event)

    begin
      forwarded = event.get(@source)

      return unless forwarded and !forwarded.empty?

      client_ip, proxies = analyse(forwarded)
      if client_ip
        event.set(@target_client_ip, client_ip)
      end
      if proxies
        event.set(@target_proxy_list, proxies)
      end
      filter_matched(event)     
      
    rescue Exception => e
      @logger.debug("Unknown error while looking up GeoIP data", :exception => e, :field => @source, :event => event)
      # raise e
    end # begin
  end # def filter

  def analyse(ip)
    if ip.nil?
      return nil, nil
    end

    if ip.is_a? Array
      ip_list = ip
    else
      ip_list = ip.downcase.split(",")  
    end
    ip_list = ip_list.map { |x| x.strip }.reject { |x| ["-", "unknown"].include? x }

    client_ip = get_client_ip(ip_list)

    if ip_list.nil?
      proxies = [] 
    else 
      proxies = ip_list - [client_ip]
    end

    return client_ip, proxies

  end # def analyse

  def get_client_ip(ip_array)
    ip_array.each do | ip |
      if ip.ipv6?
        is_private = is_private_ipv6(ip)
      else
        is_private = is_private_ipv4(ip)
      end
      if !is_private
        return ip
      end # if
    end # each
    nil
  end # get_client_ip

  
  def is_private_ipv6(ip)
    ip.start_with?("fd") || ip.start_with?("fc")
  end # is_private_ipv6


  def is_private_ipv4(ip)
    begin
      ipo = IPAddr.new(ip)
      @private_ipv4_ranges.each do | ip_range |
        if ip_range.include?(ipo)
          return true
        end
      end # each
      false
    rescue => e
      @logger.debug("Couldn't check if ip is private.", :input_data => ip, :exception => e)
    end # begin
  end # is_private

end # class LogStash::Filters::Forwarded
