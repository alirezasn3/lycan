# Lycan

Lycan is a sophisticated tool designed to trace the route packets take across the internet to reach a specific IP address. Unlike traditional traceroute applications, Lycan enriches the traceroute data with detailed information about each hop, including the country and ISP (Internet Service Provider). This feature provides users with a deeper understanding of the path their data takes, including geographical and organizational insights.

![Lycan Screenshot](screenshots/1.1.0.png)

## Features

- **Traceroute Analysis**: Discover the path packets take to reach a destination IP, with detailed hop-by-hop analysis.
- **Country and ISP Information**: Each hop is enriched with country and ISP information, offering insights into the geographical and organizational path of the packets.
- **Modern UI**: A sleek and intuitive interface built with Svelte, providing a user-friendly experience.
- **Cross-Platform Support**: Thanks to the Wails framework, Lycan can be run on various operating systems (windows installer and binary available in [releases](https://github.com/alirezasn3/lycan/releases)).

## How It Works

Lycan utilizes the ICMP protocol to send echo requests to the target IP address. For each hop along the path, the application captures the IP address and uses it to acquire detailed information about the hop's geographical location and the ISP managing it. This process is seamlessly integrated into the application's backend, written in Go, and the results are dynamically displayed on the frontend, developed with Svelte-TS.

<!-- ### Leveraging [IPEE](https://ipee.info) API
The core functionality that sets IPEE Tracer apart is its integration with the [IPEE](https://ipee.info) API. This API provides detailed information about IP addresses, including the associated country and ISP. When a hop's IP address is identified, a request is made to the API, and the response is used to enrich the traceroute data displayed to the user. This integration allows IPEE Tracer to provide a more informative and comprehensive traceroute analysis than traditional tools. -->

## License

This project is licensed under the [MIT License](LICENSE). Feel free to fork, modify, and use it in your own projects.
