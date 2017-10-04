# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/forwarded"
require "logstash/timestamp"

describe LogStash::Filters::Forwarded do

  let(:plugin) { LogStash::Filters::Forwarded.new("source" => "message") }
  
  before do
    plugin.register
    plugin.filter(event)
  end
  
  # Private IP Addresses have the following ranges:
  #10.0.0.0    - 10.255.255.255
  #172.16.0.0  - 172.31.255.255
  #192.168.0.0 - 192.168.255.255 


  context "1) multiple client ips" do

    let(:event) { LogStash::Event.new(:message => "123.45.67.89,61.160.232.222") }
    it "should take the first client ip" do
      expect(event.get("forwarded_client_ip")).to eq("123.45.67.89"), "Got #{event.inspect}"
      expect(event.get("forwarded_proxy_list")).to eq(["61.160.232.222"]), "Got #{event.inspect}"

    end # it
  end # context

  context "2) proper x-forwarded-for" do

    let(:event) { LogStash::Event.new(:message => "84.30.67.207, 10.1.2.162") }
    it "should take the first public ip" do
      expect(event.get("forwarded_client_ip")).to eq("84.30.67.207"), "Got #{event.inspect}"
      expect(event.get("forwarded_proxy_list")).to eq(["10.1.2.162"]), "Got #{event.inspect}"
    end # it
  end # context

  context "3) proper x-forwarded-for with multiple proxies" do

    let(:event) { LogStash::Event.new(:message => "94.254.183.48, 10.1.2.161, 10.1.2.162") }
    it "should take the first ip" do
      expect(event.get("forwarded_client_ip")).to eq("94.254.183.48")
      expect(event.get("forwarded_proxy_list")).to eq(["10.1.2.161","10.1.2.162"])
    end # it
  end # context

  context "4) proper x-forwarded-for with multiple proxies, no whitespace" do

    let(:event) { LogStash::Event.new(:message => "51.174.213.194,10.1.2.100,10.1.2.83") }
    it "should take the first client ip" do
      expect(event.get("forwarded_client_ip")).to eq("51.174.213.194")
      expect(event.get("forwarded_proxy_list")).to eq(["10.1.2.100","10.1.2.83"])
    end # it
  end # context

  context "5) single client ip" do

    let(:event) { LogStash::Event.new(:message => "185.22.141.112") }
    it "should set the client ip and leave the proxy list empty" do
      expect(event.get("forwarded_client_ip")).to eq("185.22.141.112")
      expect(event.get("forwarded_proxy_list")).to eq([])
    end # it
  end # context

  context "6) single proxy ip" do

    let(:event) { LogStash::Event.new(:message => "10.1.2.162") }
    it "should set the proxy list and leave the client ip empty" do
      expect(event.get("forwarded_client_ip")).to eq(nil)
      expect(event.get("forwarded_proxy_list")).to eq(["10.1.2.162"])
    end # it
  end # context

  context "7) multiple proxy ips" do

    let(:event) { LogStash::Event.new(:message => "10.1.2.162, 10.1.3.255") }
    it "should set the proxy list and leave the client ip empty" do
      expect(event.get("forwarded_client_ip")).to eq(nil)
      expect(event.get("forwarded_proxy_list")).to eq(["10.1.2.162","10.1.3.255"])
    end # it
  end # context

  context "8) empty message" do

    let(:event) { LogStash::Event.new(:message => "") }
    it "should return empty or nil values" do
      expect(event.get("forwarded_client_ip")).to eq(nil)
      expect(event.get("forwarded_proxy_list")).to eq(nil)
    end # it
  end # context

  context "9) multiple ips in wrong order" do

    let(:event) { LogStash::Event.new(:message => "10.144.80.56, 82.132.186.219") }
    it "should take the client ip from the right end of the list" do
      expect(event.get("forwarded_client_ip")).to eq("82.132.186.219")
      expect(event.get("forwarded_proxy_list")).to eq(["10.144.80.56"])
    end # it
  end # context

  context "10) edge case test for 192.x range" do

    let(:event) { LogStash::Event.new(:message => "192.168.255.255, 192.169.0.13") }
    it "should take the client ip from the right end of the list" do
      expect(event.get("forwarded_client_ip")).to eq("192.169.0.13")
      expect(event.get("forwarded_proxy_list")).to eq(["192.168.255.255"])
    end # it

  end # context

  context "11) edge case test for 172.x range" do

    let(:event) { LogStash::Event.new(:message => "172.10.0.0,172.16.0.0") }
    it "should take the client ip from the right end of the list" do
      expect(event.get("forwarded_client_ip")).to eq("172.10.0.0")
      expect(event.get("forwarded_proxy_list")).to eq(["172.16.0.0"])
    end # it

  end # context

  context "12) invalid ips in string" do

    let(:event) { LogStash::Event.new(:message => "unknown, 207.248.75.2") }
    it "should ignore the 'unknown' ip" do
      expect(event.get("forwarded_client_ip")).to eq("207.248.75.2"), "Event: #{event.inspect}"
      expect(event.get("forwarded_proxy_list")).to eq([]), "Event: #{event.inspect}"
    end # it
  end # context

  context "13) invalid ips in string pt. 2" do

    let(:event) { LogStash::Event.new(:message => "10.122.18.79, unknown, 200.152.43.203") }
    it "should ignore the 'unknown' ip" do
      expect(event.get("forwarded_client_ip")).to eq("200.152.43.203"), "Event: #{event.inspect}"
      expect(event.get("forwarded_proxy_list")).to eq(["10.122.18.79"]), "Event: #{event.inspect}"
    end # it
  end # context

  context "14) ipv4 and v6 mixed ips" do

    let(:event) { LogStash::Event.new(:message => "2405:204:828e:fa5a::e64:38a5, 64.233.173.148") }
    it "should take the client ip from the right end of the list" do
      expect(event.get("forwarded_client_ip")).to eq("2405:204:828e:fa5a::e64:38a5"), "Event: #{event.inspect}"
      expect(event.get("forwarded_proxy_list")).to eq(["64.233.173.148"]), "Event: #{event.inspect}"
    end # it
  end # context

  context "15) ipv6 private ip only" do

    let(:event) { LogStash::Event.new(:message => "fd8e:3ea6:dd4b:e20b:xxxx:xxxx:xxxx:xxxx") }
    it "should have an empty client ip" do
      expect(event.get("forwarded_client_ip")).to eq(nil), "Event: #{event.inspect}"
      expect(event.get("forwarded_proxy_list")).to eq(["fd8e:3ea6:dd4b:e20b:xxxx:xxxx:xxxx:xxxx"]), "Event: #{event.inspect}"
    end # it
  end # context

  context "16) ipv6" do

    let(:event) { LogStash::Event.new(:message => "fc8e:3ea6:dd4b:e20b:xxxx:xxxx:xxxx:xxxx,2405:204:828e:fa5a::e64:38a5") }
    it "should be able to handle ipv6 addresses" do
      expect(event.get("forwarded_client_ip")).to eq("2405:204:828e:fa5a::e64:38a5"), "Event: #{event.inspect}"
      expect(event.get("forwarded_proxy_list")).to eq(["fc8e:3ea6:dd4b:e20b:xxxx:xxxx:xxxx:xxxx"]), "Event: #{event.inspect}"
    end # it
  end # context

  context "17) override existing fields in event" do
    let(:event) { LogStash::Event.new(:message => "2405:204:828e:fa5a::e64:38a5, 127.0.0.2", :forwarded_client_ip => "127.0.0.1") }
    it "should ignore the old value for the forwarded_client_ip" do
      expect(event.get("forwarded_client_ip")).to eq("2405:204:828e:fa5a::e64:38a5"), "Event: #{event.inspect}"
      expect(event.get("forwarded_proxy_list")).to eq(["127.0.0.2"]), "Event: #{event.inspect}"
    end # it
  end # context

  context "18) input field doesn't exist" do
    let(:event) { LogStash::Event.new() }
    it "should not raise an exception" do
      expect {plugin.filter(event)}.not_to raise_error
    end # it
  end # context

  context "19) unresolved host names" do
    let(:event) { LogStash::Event.new(:message => "192.168.4.61,wmt00091.kan,wmt00091.kan, 64.134.227.116") }
    it "should drop the unresolved hosts" do
      expect(event.get("forwarded_client_ip")).to eq("64.134.227.116"), "Event: #{event.inspect}"
      expect(event.get("forwarded_proxy_list")).to eq(["192.168.4.61","wmt00091.kan","wmt00091.kan"]), "Event: #{event.inspect}"
    end # it
  end # context

  context "20) ip field is an array" do
    let(:event) { LogStash::Event.new(:message => ["51.174.213.194","10.1.2.100","10.1.2.83"]) }
    it "should take the first client ip" do
      expect(event.get("forwarded_client_ip")).to eq("51.174.213.194")
      expect(event.get("forwarded_proxy_list")).to eq(["10.1.2.100","10.1.2.83"])
    end # it
  end # context

  context "21) ip has a port number" do
    let(:event) { LogStash::Event.new(:message => ["51.174.213.194:8080","10.1.2.100","10.1.2.83:80"]) }
    it "should remove the port numbers" do
      expect(event.get("forwarded_client_ip")).to eq("51.174.213.194")
      expect(event.get("forwarded_proxy_list")).to eq(["10.1.2.100","10.1.2.83"])
    end # it
  end # context

  context "22) multiple client ips with port number" do
    let(:event) { LogStash::Event.new(:message => "123.45.67.89:8080,61.160.232.222:123") }
    it "should remove the port numbers" do
      expect(event.get("forwarded_client_ip")).to eq("123.45.67.89")
      expect(event.get("forwarded_proxy_list")).to eq(["61.160.232.222"])

    end # it
  end # context

end