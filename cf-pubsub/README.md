# TeamMulticast-CoAP-PubSub
This was part of Multicast team's project for the course II1305 at KTH.

The goal of the project is to implement the IETS's RFC for CoAP publish-subscribe as an API/library for general use alongside Californium, and then build a front-end client Android app to show live data published from a network of sensors through a broker to subscribed clients using the aforementioned API. 
The project is commissioned by the KTH Network Systems Laboratory. You can read more about it here: https://www.kth.se/cos/research/nslab

You can take a look at the IETS's RFC for CoAP publish-subscribe draft here: https://www.ietf.org/id/draft-ietf-core-coap-pubsub-08.txt

You can follow along our Project progress here: https://sites.google.com/view/team-multicast/home

You can see the repository for the Android app here: https://github.com/ihilal/Noisy

This library is meant to be used alongside The Californium Library.

## Available functionality:
- Discover: allows you to find a list of available topics on the broker
    - You may provide a query to limit the list you get back
    - If ```rt=core.ps``` is provided as a query, you can check whether the broker supports CoAP Publish-Subscribe
- Create: allows you to create a new topic on the broker with the given uri and name and content type
- Publish: allows you to publish content to the given uri of a topic on the broker
- Read: allows you to read the content on the specified topic uri
- Remove: allows you to remove a topic on the broker
- Subscription: given a topic uri and a listener (CoapHandler), it allows you to:
    - Subscribe to the given topic
    - Unsubscribe from the given topic
- Two classes available to help with using PubSub core functions using different styles:
    - Converter
    - Topic
    - check their documentation for how to use them

## Installation:

##Examples
```
PubSub pubsub = new PubSub("127.0.0.1"); 
OR
PubSub pubsub = new PubSub("127.0.0.1", 5683, 5000); 

CoapResponse response = pubsub.discover("rt=core.ps");

response = pubsub.create("topic", 40, "ps");
response = pubsub.create("topic1", 0, "ps/topic/");

response = pubsub.discover();

Set<WebLink> topics = Converter.getWebLinks(response);
OR
ArrayList<Topic> at = Topic.makeArrayList(LinkFormat.parse(response.getResponseText()));

response = pubsub.publish("content", 0, "ps/topic/topic1");

String content = pubsub.read("ps/topic/topic1").getResponseText();

CoapHandler handler = new CoapHandler() {
    @Override
    public void onLoad(CoapResponse coapResponse) {
        System.out.println("topic content: " + coapResponse.getResponseText());
    }

    @Override
    public void onError() {
        System.out.println("ERROR");
    }
};

PubSub.Subscription subscription = pubsub.new Subscription(handler, "ps/topic/topic1");

subscription.subscribe();

subscription.unsubscribe();

response = pubsub.remove("ps/topic/topic1");
```

## Support: 

## Contributing:

## Authors and Acknowledgements:
- Petr Kocián
- Ahmad Hussain
- Ismail Hilal
- Matias Carlander-Reuterfelt Gallo
- Wajd Tohme
- Zainab Al-Saadi
- Tuna Gersil

## License: 


## Project Status:
This project was developed for the course II1305 at KTH and the course is over, so the project will likely not develop further but you are welcome to contribute to it further