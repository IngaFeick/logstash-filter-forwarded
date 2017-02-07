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
        expect(event.get("client_ip")).to eq("123.45.67.89")
        expect(event.get("proxies")).to eq(["61.160.232.222"])
      end # it
    end # context

    context "proper x-forwarded-for" do

      let(:event) { LogStash::Event.new(:message => "84.30.67.207, 10.1.2.162") }
      it "should take the first public ip" do
        expect(event.get("client_ip")).to eq("84.30.67.207")
        expect(event.get("proxies")).to eq(["10.1.2.162"])
      end # it
    end # context

    context "proper x-forwarded-for with multiple proxies" do

      let(:event) { LogStash::Event.new(:message => "94.254.183.48, 10.1.2.161, 10.1.2.162") }
      it "should take the first ip" do
        expect(event.get("client_ip")).to eq("94.254.183.48")
        expect(event.get("proxies")).to eq(["10.1.2.161","10.1.2.162"])
      end # it
    end # context

    context "proper x-forwarded-for with multiple proxies, no whitespace" do

      let(:event) { LogStash::Event.new(:message => "51.174.213.194,10.1.2.100,10.1.2.83") }
      it "should take the first client ip" do
        expect(event.get("client_ip")).to eq("51.174.213.194")
        expect(event.get("proxies")).to eq(["10.1.2.100","10.1.2.83"])
      end # it
    end # context

    context "single client ip" do

      let(:event) { LogStash::Event.new(:message => "185.22.141.112") }
      it "should set the client ip and leave the proxy list empty" do
        expect(event.get("client_ip")).to eq("185.22.141.112")
        expect(event.get("proxies")).to eq([])
      end # it
    end # context

    context "single proxy ip" do

      let(:event) { LogStash::Event.new(:message => "10.1.2.162") }
      it "should set the proxy list and leave the client ip empty" do
        expect(event.get("client_ip")).to eq(nil)
        expect(event.get("proxies")).to eq(["10.1.2.162"])
      end # it
    end # context

    context "multiple proxy ips" do

      let(:event) { LogStash::Event.new(:message => "10.1.2.162, 10.1.3.255") }
      it "should set the proxy list and leave the client ip empty" do
        expect(event.get("client_ip")).to eq(nil)
        expect(event.get("proxies")).to eq(["10.1.2.162","10.1.3.255"])
      end # it
    end # contex

    context "empty message" do

      let(:event) { LogStash::Event.new(:message => "") }
      it "should return empty or nil values" do
        expect(event.get("client_ip")).to eq(nil)
        expect(event.get("proxies")).to eq(nil)
      end # it
    end # contex

    context "multiple ips in wrong order" do

      let(:event) { LogStash::Event.new(:message => "10.144.80.56, 82.132.186.219") }
      it "should take the client ip from the right end of the list" do
        expect(event.get("client_ip")).to eq("82.132.186.219")
        expect(event.get("proxies")).to eq(["10.144.80.56"])
      end # it
    end # contex

    context "ipv6 client ip" do

      let(:event) { LogStash::Event.new(:message => "2405:204:828e:fa5a::e64:38a5, 64.233.173.148") }
      it "should take the client ip from the right end of the list" do
        expect(event.get("client_ip")).to eq("2405:204:828e:fa5a::e64:38a5")
        expect(event.get("proxies")).to eq(["64.233.173.148"])
      end # it
    end # contex

# TODO add more use cases for ipv6 and for the bug report from the github ticket
#[2017-02-06T18:02:45,832][WARN ][logstash.filters.forwarded] Invalid IP network, skipping {:adress=>"10/8"}
#[2017-02-06T18:02:45,838][WARN ][logstash.filters.forwarded] Invalid IP network, skipping {:adress=>"192.168/16"}

# TODO add edge cases for the following
# Private IP Addresses have the following ranges:
#10.0.0.0    - 10.255.255.255
#172.16.0.0  - 172.31.255.255
#192.168.0.0 - 192.168.255.255 

end