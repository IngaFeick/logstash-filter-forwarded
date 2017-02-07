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
    
    context "multiple client ips" do

      let(:event) { LogStash::Event.new(:message => "123.45.67.89,61.160.232.222") }
      it "should take the first client ip" do
        expect(event.get("forwarded_client_ip")).to eq("123.45.67.89")
        expect(event.get("forwarded_proxy_list")).to eq(["61.160.232.222"])
      end # it
    end # context

    context "proper x-forwarded-for" do

      let(:event) { LogStash::Event.new(:message => "84.30.67.207, 10.1.2.162") }
      it "should take the first public ip" do
        expect(event.get("forwarded_client_ip")).to eq("84.30.67.207")
        expect(event.get("forwarded_proxy_list")).to eq(["10.1.2.162"])
      end # it
    end # context

    context "proper x-forwarded-for with multiple proxies" do

      let(:event) { LogStash::Event.new(:message => "94.254.183.48, 10.1.2.161, 10.1.2.162") }
      it "should take the first ip" do
        expect(event.get("forwarded_client_ip")).to eq("94.254.183.48")
        expect(event.get("forwarded_proxy_list")).to eq(["10.1.2.161","10.1.2.162"])
      end # it
    end # context

    context "proper x-forwarded-for with multiple proxies, no whitespace" do

      let(:event) { LogStash::Event.new(:message => "51.174.213.194,10.1.2.100,10.1.2.83") }
      it "should take the first client ip" do
        expect(event.get("forwarded_client_ip")).to eq("51.174.213.194")
        expect(event.get("forwarded_proxy_list")).to eq(["10.1.2.100","10.1.2.83"])
      end # it
    end # context

    context "single client ip" do

      let(:event) { LogStash::Event.new(:message => "185.22.141.112") }
      it "should set the client ip and leave the proxy list empty" do
        expect(event.get("forwarded_client_ip")).to eq("185.22.141.112")
        expect(event.get("forwarded_proxy_list")).to eq([])
      end # it
    end # context

    context "single proxy ip" do

      let(:event) { LogStash::Event.new(:message => "10.1.2.162") }
      it "should set the proxy list and leave the client ip empty" do
        expect(event.get("forwarded_client_ip")).to eq(nil)
        expect(event.get("forwarded_proxy_list")).to eq(["10.1.2.162"])
      end # it
    end # context

    context "multiple proxy ips" do

      let(:event) { LogStash::Event.new(:message => "10.1.2.162, 10.1.3.255") }
      it "should set the proxy list and leave the client ip empty" do
        expect(event.get("forwarded_client_ip")).to eq(nil)
        expect(event.get("forwarded_proxy_list")).to eq(["10.1.2.162","10.1.3.255"])
      end # it
    end # context

    context "empty message" do

      let(:event) { LogStash::Event.new(:message => "") }
      it "should return empty or nil values" do
        expect(event.get("forwarded_client_ip")).to eq(nil)
        expect(event.get("forwarded_proxy_list")).to eq(nil)
      end # it
    end # context

    context "multiple ips in wrong order" do

      let(:event) { LogStash::Event.new(:message => "10.144.80.56, 82.132.186.219") }
      it "should take the client ip from the right end of the list" do
        expect(event.get("forwarded_client_ip")).to eq("82.132.186.219")
        expect(event.get("forwarded_proxy_list")).to eq(["10.144.80.56"])
      end # it
    end # context

    context "edge case test for 192.x range" do

    # Private IP Addresses have the following ranges:
    #10.0.0.0    - 10.255.255.255
    #172.16.0.0  - 172.31.255.255
    #192.168.0.0 - 192.168.255.255 

      let(:event) { LogStash::Event.new(:message => "192.168.255.255, 192.169.0.13") }
      it "should take the client ip from the right end of the list" do
        expect(event.get("forwarded_client_ip")).to eq("192.169.0.13")
        expect(event.get("forwarded_proxy_list")).to eq(["192.168.255.255"])
      end # it

    end # context

    context "edge case test for 172.x range" do

      let(:event) { LogStash::Event.new(:message => "172.10.0.0,172.16.0.0") }
      it "should take the client ip from the right end of the list" do
        expect(event.get("forwarded_client_ip")).to eq("172.10.0.0")
        expect(event.get("forwarded_proxy_list")).to eq(["172.16.0.0"])
      end # it

    end # context

    context "ipv6 client ip" do

      let(:event) { LogStash::Event.new(:message => "2405:204:828e:fa5a::e64:38a5, 64.233.173.148") }
      it "should take the client ip from the right end of the list" do
        expect(event.get("forwarded_client_ip")).to eq("2405:204:828e:fa5a::e64:38a5")
        expect(event.get("forwarded_proxy_list")).to eq(["64.233.173.148"])
      end # it
    end # context

# TODO add more use cases for ipv6
# TODO add edge cases for the following


end