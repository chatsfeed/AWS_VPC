# To get the name servers for our zone to put in our domain registrar.
output "example_name_servers" {  
  value = "${aws_route53_zone.main.name_servers}"
}
