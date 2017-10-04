# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "ipaddr" # needed for network range check
require "ipaddress" # needed for validity check

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
      
      event.set(@target_client_ip, client_ip) if client_ip
      event.set(@target_proxy_list, proxies) if proxies
      filter_matched(event)     
      
    rescue Exception => e
      @logger.debug("Unknown error while looking up GeoIP data", :exception => e, :field => @source, :event => event)
      # raise e
    end # begin
  end # def filter

  def analyse(ip)
    return nil, nil if ip.nil?
      # convert the x-forwarded-for string into an array of its comma separated value, if it isn't already.
      ip_list = ip.is_a?(Array) ? ip : ip.downcase.split(",")  

      # remove some well-known invalid values
      ip_list = ip_list.map { |x| x.strip }.reject { |x| ["-", "unknown"].include? x}

      # the IpAddr library cannot handle ips with port numbers
      ip_list = ip_list.map { |x| remove_port_number(x) }

      # get the first public ip in the list
      client_ip = get_client_ip(ip_list)
      
      # remove the public / client ip from the list and use the remainder as the list of proxies involved.
      proxies = ip_list.nil? ? [] : ip_list - [client_ip]
      
      return client_ip, proxies
  end # def analyse

  def get_client_ip(ip_array)
      ip_array.each do | ip |
        begin          
          next if !IPAddress.valid? ip

          ipo = IPAddr.new(ip)            
          is_private = ipo.ipv6? ? is_private_ipv6(ip) : is_private_ipv4(ipo)         
          return ip if !is_private
        rescue => e
          # not a valid ip, moving on.
          # @logger.debug("get_client_ip() failed", :exception => e, :field => @source, :ip_array => ip_array)
          next
        end
      end # each
      nil
  end # get_client_ip

  def remove_port_number(ip)
    tokens = ip.split(":")
    if tokens.size <=2 then tokens[0] else ip end
  end
  
  def is_private_ipv6(ip)
    ip.start_with?("fd") || ip.start_with?("fc")
  end # is_private_ipv6


  def is_private_ipv4(ipo)
    begin
      @private_ipv4_ranges.each do | ip_range |
        return true if ip_range.include?(ipo)
      end # each
      false
    rescue => e
      @logger.debug("Couldn't check if ip is private.", :input_data => ip, :exception => e)
    end # begin
  end # is_private

end # class LogStash::Filters::Forwarded
