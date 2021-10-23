
provider "aws" {
   region  = var.aws_region
   access_key = var.access_key
   secret_key = var.secret_key
}


# ------------------------------------------------------------------------------
# CONFIGURE TERRAFORM BACKEND
# ------------------------------------------------------------------------------
terraform {
  backend "s3" {
    # Replace this with your bucket name!
    bucket         = "chatsfeed-terraform-remote-state-s3"
    key            = "terraform.tfstate"
    region  = "us-east-2"
    # Replace this with your DynamoDB table name!
    dynamodb_table = "chatsfeed-terraform-remote-state-s3-locks"
    encrypt        = true
  }
  # An argument named "depends_on" is not expected here
  # this is why we first have to create those resources to then run our terraform with remote state in s3
  # the state file will be local on the first run to create the resources, then will be remote on the second run
  #depends_on = [aws_s3_bucket.terraform_state, aws_dynamodb_table.terraform_locks]
}


# We can set up multiple providers and use them for creating resources in different regions or in different AWS accounts by creating aliases.
# Some AWS services require the us-east-1 (N. Virginia) region to be configured:
# To use an ACM certificate with CloudFront, we must request or import the certificate in the US East (N. Virginia) region.
provider "aws" {
  alias  = "us-east-1"
  region = "us-east-1"
  access_key = var.access_key
  secret_key = var.secret_key 
}



## AWS Route53 is a DNS service used to perform three main functions: domain registration, DNS routing, and health checking.
# The first step to configure the DNS service for our domain (eg: example.com) is to create the public hosted zone 
# the name server (NS) record, and the start of a zone of authority (SOA) record are automatically created by AWS
resource  "aws_route53_zone" "main" {
  name         = var.website-domain
}


# We use ACM (AWS Certificate Manager) to create the wildcard certificate *.<yourdomain.com>
# This resource won't be created until we receive the email verifying we own the domain and we click on the confirmation link.
resource "aws_acm_certificate" "wildcard_website" {
  # We refer to the aliased provider ( ${provider_name}.${alias} ) for creating our ACM resource. 
  provider                  = aws.us-east-1
  # We want a wildcard cert so we can host subdomains later.
  domain_name       = "*.${var.website-domain}" 
  # We also want the cert to be valid for the root domain even though we'll be redirecting to the www. domain immediately.
  subject_alternative_names = ["${var.website-domain}"]
  # Which method to use for validation. DNS or EMAIL are valid, NONE can be used for certificates that were imported into ACM and then into Terraform. 
  validation_method         = "EMAIL"

  # (Optional) A mapping of tags to assign to the resource. 
  tags = merge(var.tags, {
    ManagedBy = "terraform"
    Changed   = formatdate("YYYY-MM-DD hh:mm ZZZ", timestamp())
  })

  # The lifecycle block is available for all resource blocks regardless of type
  # create_before_destroy(bool), prevent_destroy(bool), and ignore_changes(list of attribute names)
  # to be used when a resource is created with references to data that may change in the future, but should not affect said resource after its creation 
  lifecycle {
    ignore_changes = [tags["Changed"]]
  }

}


# This resource is simply a waiter for manual email approval of ACM certificates.
# We use the aws_acm_certificate_validation resource to wait for the newly created certificate to become valid
# and then use its outputs to associate the certificate Amazon Resource Name (ARN) with the CloudFront distribution
# The certificate Amazon Resource Name (ARN) provided by aws_acm_certificate looks identical, but is almost always going to be invalid right away. 
# Using the output from the validation resource ensures that Terraform will wait for ACM to validate the certificate before resolving its ARN.
resource "aws_acm_certificate_validation" "wildcard_cert" {
  provider                = aws.us-east-1
  certificate_arn         = aws_acm_certificate.wildcard_website.arn
}


## Find a certificate that is issued
## Get the ARN of the issued certificate in AWS Certificate Manager (ACM)
data "aws_acm_certificate" "wildcard_website" {
  provider = aws.us-east-1

  # This argument is available for all resource blocks, regardless of resource type
  # Necessary when a resource or module relies on some other resource's behavior but doesn't access any of that resource's data in its arguments
  depends_on = [
    aws_acm_certificate.wildcard_website,
    aws_acm_certificate_validation.wildcard_cert,
  ]

  # (Required) The domain of the certificate to look up 
  domain      = "*.${var.website-domain}" #var.www-website-domain 
  # (Optional) A list of statuses on which to filter the returned list. Default is ISSUED if no value is specified
  # Valid values are PENDING_VALIDATION, ISSUED, INACTIVE, EXPIRED, VALIDATION_TIMED_OUT, REVOKED and FAILED 
  statuses    = ["ISSUED"]
  # Returning only the most recent one 
  most_recent = true
}

## CloudFront
# Creates the CloudFront distribution to serve the static website
resource "aws_cloudfront_distribution" "website_cdn_root" {
  enabled     = true
  # (Optional) - The price class for this distribution. One of PriceClass_All, PriceClass_200, PriceClass_100 
  price_class = "PriceClass_All"
  # (Optional) - Extra CNAMEs (alternate domain names), if any, for this distribution 
  aliases = [var.www-website-domain, var.app-website-domain]

  # Origin is where CloudFront gets its content from 
  origin {
    origin_id   = aws_alb.load_balancer.id 
    domain_name = var.website-domain

    custom_origin_config {
      # The protocol policy that you want CloudFront to use when fetching objects from the origin server (a.k.a S3 in our situation). 
      # HTTP Only is the default setting when the origin is an Amazon S3 static website hosting endpoint
      # This is because Amazon S3 doesn’t support HTTPS connections for static website hosting endpoints. 
      origin_protocol_policy = "https-only"
      http_port            = 80
      https_port           = 443
      origin_ssl_protocols = ["TLSv1.2", "TLSv1.1", "TLSv1"]
    }
  }

  #optional 
  #default_root_object = "index.html"

  logging_config {
    bucket = aws_s3_bucket.website_logs.bucket_domain_name
    prefix = "${var.www-website-domain}/"
  }

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "DELETE"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    # This needs to match the `origin_id` above 
    target_origin_id = aws_alb.load_balancer.id 
    min_ttl          = "0"
    default_ttl      = "300"
    max_ttl          = "1200"

    # Redirects any HTTP request to HTTPS 
    #viewer_protocol_policy = "redirect-to-https" 
    viewer_protocol_policy = "allow-all" 
    compress               = true

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn = data.aws_acm_certificate.wildcard_website.arn
    ssl_support_method  = "sni-only"
  }

  #optional 
  #custom_error_response {
    #error_caching_min_ttl = 300
    #error_code            = 404
    #response_page_path    = "/404.html"
    #response_code         = 404
  #}

  tags = merge(var.tags, {
    ManagedBy = "terraform"
    Changed   = formatdate("YYYY-MM-DD hh:mm ZZZ", timestamp())
  })

  lifecycle {
    ignore_changes = [
      tags["Changed"],
      viewer_certificate,
    ]
  }
}


# Creates the DNS record to point on the main CloudFront distribution ID
resource "aws_route53_record" "website_cdn_root_record" {
  #zone_id = data.aws_route53_zone.wildcard_website.zone_id
  zone_id = "${aws_route53_zone.main.zone_id}"
  name    = var.www-website-domain
  type    = "A"

  alias {
    name = aws_cloudfront_distribution.website_cdn_root.domain_name
    zone_id = aws_cloudfront_distribution.website_cdn_root.hosted_zone_id
    evaluate_target_health = false
  }
}



# Creates bucket to store logs
resource "aws_s3_bucket" "website_logs" {
  bucket = "${var.www-website-domain}-logs"
  acl    = "log-delivery-write"

  # Comment the following line if you are uncomfortable with Terraform destroying the bucket even if this one is not empty
  force_destroy = true


  tags = merge(var.tags, {
    ManagedBy = "terraform"
    Changed   = formatdate("YYYY-MM-DD hh:mm ZZZ", timestamp())
  })

  lifecycle {
    ignore_changes = [tags["Changed"]]
  }
}



# We create a new VPC
resource "aws_vpc" "vpc" {
   cidr_block = var.vpc_cidr 
   instance_tenancy = "default"
   tags = {
      Name = "VPC"
   }
   enable_dns_hostnames = true
}

# We create a public subnet in AZ 1
# Instances will have a dynamic public IP and be accessible via the internet gateway
resource "aws_subnet" "public_subnet_1" {
   depends_on = [
      aws_vpc.vpc,
   ]
   vpc_id = aws_vpc.vpc.id
   cidr_block = var.public_subnet_1_CIDR
   availability_zone_id = var.AZ_1
   tags = {
      Name = "public-subnet-1"
   }
   map_public_ip_on_launch = true
}


# We create a public subnet in AZ 2
# Instances will have a dynamic public IP and be accessible via the internet gateway
resource "aws_subnet" "public_subnet_2" {
   depends_on = [
      aws_vpc.vpc,
   ]
   vpc_id = aws_vpc.vpc.id
   cidr_block = var.public_subnet_2_CIDR
   availability_zone_id = var.AZ_2
   tags = {
      Name = "public-subnet-2"
   }
   map_public_ip_on_launch = true
}

# We create a private subnet in AZ 1
# Instances will not be accessible via the internet gateway
resource "aws_subnet" "private_subnet_1" {
   depends_on = [
      aws_vpc.vpc,
   ]
   vpc_id = aws_vpc.vpc.id
   cidr_block = var.private_subnet_1_CIDR
   availability_zone_id = var.AZ_1
   tags = {
      Name = "private-subnet-1"
   }
}

# We create a private subnet in AZ 2
# Instances will not be accessible via the internet gateway
resource "aws_subnet" "private_subnet_2" {
   depends_on = [
      aws_vpc.vpc,
   ]
   vpc_id = aws_vpc.vpc.id
   cidr_block = var.private_subnet_2_CIDR
   availability_zone_id = var.AZ_2
   tags = {
      Name = "private-subnet-2"
   }
}

# We create an internet gateway
# Allows communication between our VPC and the internet
resource "aws_internet_gateway" "internet_gateway" {
   depends_on = [
      aws_vpc.vpc,
   ]
   vpc_id = aws_vpc.vpc.id
   tags = {
      Name = "internet-gateway",
   }
}

# We need 1 public routetable because it is associated to the same intenet gateway id

# We create a route table with target as our internet gateway and destination as "internet"
# Set of rules used to determine where network traffic is directed
resource "aws_route_table" "IG_route_table" {
   depends_on = [
      aws_vpc.vpc,
      aws_internet_gateway.internet_gateway,
   ]
   vpc_id = aws_vpc.vpc.id
   route {
      cidr_block = "0.0.0.0/0"
      gateway_id = aws_internet_gateway.internet_gateway.id
   }
   tags = {
      Name = "IG-route-table"
   }
}


# We associate our route table to the public subnet in AZ 1
# Makes the subnet public because it has a route to the internet via our internet gateway
resource "aws_route_table_association" "associate_routetable_to_public_subnet_1" {
   depends_on = [
      aws_subnet.public_subnet_1,
      aws_route_table.IG_route_table,
   ]
   subnet_id = aws_subnet.public_subnet_1.id
   route_table_id = aws_route_table.IG_route_table.id
}

# We associate our route table to the public subnet in AZ 2
# Makes the subnet public because it has a route to the internet via our internet gateway
resource "aws_route_table_association" "associate_routetable_to_public_subnet_2" {
   depends_on = [
      aws_subnet.public_subnet_2,
      aws_route_table.IG_route_table,
   ]
   subnet_id = aws_subnet.public_subnet_2.id
   route_table_id = aws_route_table.IG_route_table.id
}

# We create an elastic IP for our NAT gateway in public subnet AZ 1
# A static public IP address that we can assign to any EC2 instance
resource "aws_eip" "elastic_ip_1" {
   vpc = true
}

# We create an elastic IP for our NAT gateway in public subnet AZ 2
# A static public IP address that we can assign to any EC2 instance
resource "aws_eip" "elastic_ip_2" {
   vpc = true
}

# We create a NAT gateway with a required public IP in public subnet AZ 1
# Lives in a public subnet and prevents externally initiated traffic to our private subnet
# Allows initiated outbound traffic to the Internet or other AWS services
resource "aws_nat_gateway" "nat_gateway_1" {
   depends_on = [
      aws_subnet.public_subnet_1,
      aws_eip.elastic_ip_1,
   ]
   allocation_id = aws_eip.elastic_ip_1.id
   subnet_id = aws_subnet.public_subnet_1.id
   tags = {
      Name = "nat-gateway-1"
   }
}

# We create a NAT gateway with a required public IP in public subnet AZ 2
# Lives in a public subnet and prevents externally initiated traffic to our private subnet
# Allows initiated outbound traffic to the Internet or other AWS services
resource "aws_nat_gateway" "nat_gateway_2" {
   depends_on = [
      aws_subnet.public_subnet_2,
      aws_eip.elastic_ip_2,
   ]
   allocation_id = aws_eip.elastic_ip_2.id
   subnet_id = aws_subnet.public_subnet_2.id
   tags = {
      Name = "nat-gateway-2"
   }
}

# We need 2 private routetables because each is associated to a specific NAT gateway id

# We create a route table with target as NAT gateway 1 and destination as "internet"
# Set of rules used to determine where network traffic is directed
resource "aws_route_table" "NAT_route_table_1" {
   depends_on = [
      aws_vpc.vpc,
      aws_nat_gateway.nat_gateway_1,
   ]
   vpc_id = aws_vpc.vpc.id
   route {
      cidr_block = "0.0.0.0/0"
      gateway_id = aws_nat_gateway.nat_gateway_1.id
   }
   tags = {
      Name = "NAT-route-table-1"
   }
}

# We create a route table with target as NAT gateway 2 and destination as "internet"
# Set of rules used to determine where network traffic is directed
resource "aws_route_table" "NAT_route_table_2" {
   depends_on = [
      aws_vpc.vpc,
      aws_nat_gateway.nat_gateway_2,
   ]
   vpc_id = aws_vpc.vpc.id
   route {
      cidr_block = "0.0.0.0/0"
      gateway_id = aws_nat_gateway.nat_gateway_2.id
   }
   tags = {
      Name = "NAT-route-table-2"
   }
}

# We associate our NAT route table to the private subnet 1 in AZ 1
# Keeps the subnet private because it has a route to the internet via our NAT gateway 
resource "aws_route_table_association" "associate_routetable_to_private_subnet_1" {
   depends_on = [
      aws_subnet.private_subnet_1,
      aws_route_table.NAT_route_table_1,
   ]
   subnet_id = aws_subnet.private_subnet_1.id
   route_table_id = aws_route_table.NAT_route_table_1.id
}

# We associate our NAT route table to the private subnet 2 in AZ 2
# Keeps the subnet private because it has a route to the internet via our NAT gateway
resource "aws_route_table_association" "associate_routetable_to_private_subnet_2" {
   depends_on = [
      aws_subnet.private_subnet_2,
      aws_route_table.NAT_route_table_2,
   ]
   subnet_id = aws_subnet.private_subnet_2.id
   route_table_id = aws_route_table.NAT_route_table_2.id
}

# We create a security group for SSH traffic
# EC2 instances' firewall that controls incoming and outgoing traffic
resource "aws_security_group" "sg_bastion_host" {
   depends_on = [
      aws_vpc.vpc,
   ]
   name = "sg bastion host"
   description = "bastion host security group"
   vpc_id = aws_vpc.vpc.id
   ingress {
      description = "allow ssh"
      from_port = 22
      to_port = 22
      protocol = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
   }
   ingress {
      description = "allow cloudMapper"
      from_port = 8000
      to_port = 8000
      protocol = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
   }
   egress {
      from_port = 0
      to_port = 0
      protocol = "-1"
      cidr_blocks = ["0.0.0.0/0"]
   }
   tags = {
      Name = "sg bastion host"
   }
}

# We create an elastic IP for our bastion host in public subnet 1 in AZ 1
# A static public IP address that we can assign to our bastion host
resource "aws_eip" "bastion_elastic_ip_1" {
   vpc = true
}

# We create an elastic IP for our bastion host in public subnet 2 in AZ 2
# A static public IP address that we can assign to our bastion host
resource "aws_eip" "bastion_elastic_ip_2" {
   vpc = true
}

# We create an ssh key using the RSA algorithm with 4096 rsa bits
# The ssh key always includes the public and the private key
resource "tls_private_key" "ssh_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# We upload the public key of our created ssh key to AWS
resource "aws_key_pair" "public_ssh_key" {
  key_name   = var.public_key_name
  public_key = tls_private_key.ssh_key.public_key_openssh

   depends_on = [tls_private_key.ssh_key]
}

# We save our public key at our specified path.
# Can upload on remote server for ssh encryption
resource "local_file" "save_public_key" {
  content = tls_private_key.ssh_key.public_key_openssh 
  filename = "${var.key_path}${var.public_key_name}.pem"
}

# We save our private key at our specified path.
# Allows private key instead of a password to securely access our instances
resource "local_file" "save_private_key" {
  content = tls_private_key.ssh_key.private_key_pem
  filename = "${var.key_path}${var.private_key_name}.pem"
}

# We create a bastion host in public subnet 1 in AZ 1
# Allows SSH into instances in private subnet
resource "aws_instance" "bastion_host_1" {
   depends_on = [
      aws_security_group.sg_bastion_host,
   ]
   ami = var.ec2_ami
   instance_type = var.ec2_type
   key_name = aws_key_pair.public_ssh_key.key_name
   vpc_security_group_ids = [aws_security_group.sg_bastion_host.id]
   subnet_id = aws_subnet.public_subnet_1.id
   tags = {
      Name = "bastion host 1"
   }
   provisioner "file" {
    source      = "${var.key_path}${var.private_key_name}.pem"
    destination = "/home/ubuntu/private_ssh_key.pem"

    connection {
    type     = "ssh"
    user     = "ubuntu"
    private_key = tls_private_key.ssh_key.private_key_pem
    host     = aws_instance.bastion_host_1.public_ip
    }
  }
}

# We create a bastion host in public subnet 2 in AZ 2
# Allows SSH into instances in private subnet
resource "aws_instance" "bastion_host_2" {
   depends_on = [
      aws_security_group.sg_bastion_host,
   ]
   ami = var.ec2_ami
   instance_type = var.ec2_type
   key_name = aws_key_pair.public_ssh_key.key_name
   vpc_security_group_ids = [aws_security_group.sg_bastion_host.id]
   subnet_id = aws_subnet.public_subnet_2.id
   tags = {
      Name = "bastion host 2"
   }
   provisioner "file" {
    source      = "${var.key_path}${var.private_key_name}.pem"
    destination = "/home/ubuntu/private_ssh_key.pem"

    connection {
    type     = "ssh"
    user     = "ubuntu"
    private_key = tls_private_key.ssh_key.private_key_pem
    host     = aws_instance.bastion_host_2.public_ip
    }
  }
}


# We associate the elastic ip to our bastion host 1
resource "aws_eip_association" "bastion_eip_association_1" {
  instance_id   = aws_instance.bastion_host_1.id
  allocation_id = aws_eip.bastion_elastic_ip_1.id
}

# We associate the elastic ip to our bastion host 2
resource "aws_eip_association" "bastion_eip_association_2" {
  instance_id   = aws_instance.bastion_host_2.id
  allocation_id = aws_eip.bastion_elastic_ip_2.id
}

# We save our bastion host ip in a file.
resource "local_file" "ip_addresses" {
  content = <<EOF
            Bastion host 1 public ip address: ${aws_eip.bastion_elastic_ip_1.public_ip}
            Bastion host 1 private ip address: ${aws_instance.bastion_host_1.private_ip}
            Bastion host 2 public ip address: ${aws_eip.bastion_elastic_ip_2.public_ip}
            Bastion host 2 private ip address: ${aws_instance.bastion_host_2.private_ip}
  EOF
  filename = "${var.key_path}ip_addresses.txt"
}

# We create a security group for our application load balancer
# EC2 instances' firewall that controls incoming and outgoing traffic
resource "aws_security_group" "sg_load_balancer" {
  name        = "security group load balancer"
  description = "Allow all inbound traffic"
  vpc_id     = aws_vpc.vpc.id

 # HTTP access from anywhere
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
 # HTTPS access from anywhere
 ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  } 

 # Outbound all traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "sg-load-balancer"
  }

  depends_on = [
    aws_vpc.vpc
  ]
}


# We create a target group for our application load balancer
resource "aws_alb_target_group" "tg_load_balancer_http" {
  name     = "target-group-load-balancer-http"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.vpc.id

  depends_on = [
    aws_vpc.vpc
  ]
}

resource "aws_alb_target_group" "tg_load_balancer_https" {
  name     = "target-group-load-balancer-https"
  port     = 443
  protocol = "HTTPS"
  vpc_id   = aws_vpc.vpc.id

  depends_on = [
    aws_vpc.vpc
  ]
}

# We create our application load balancer
resource "aws_alb" "load_balancer" {
  name               = "load-balancer"
  provider                = aws.us-east-1 
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.sg_load_balancer.id]
  subnets            = [aws_subnet.public_subnet_1.id, aws_subnet.public_subnet_2.id]

  enable_deletion_protection = false

  tags = {
    Environment = "production"
  }

  depends_on = [
    aws_security_group.sg_load_balancer,
    aws_subnet.public_subnet_1,
    aws_subnet.public_subnet_2
  ]
}


# We create an http listener for our application load balancer
resource "aws_alb_listener" "listener_load_balancer_http" {
  load_balancer_arn = aws_alb.load_balancer.id
  provider                = aws.us-east-1 
  port              = "80"
  protocol          = "HTTP"
  
  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
 
  depends_on = [
    aws_alb.load_balancer,
    aws_alb_target_group.tg_load_balancer_http
  ]
}

# We create an https listener for our application load balancer
resource "aws_alb_listener" "listener_load_balancer_https" {
  load_balancer_arn = aws_alb.load_balancer.id
  provider                = aws.us-east-1 
  port              = "443"
  protocol          = "HTTPS"
  
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  # Default certificate
  certificate_arn   = data.aws_acm_certificate.wildcard_website.arn
   
  default_action {
    target_group_arn = aws_alb_target_group.tg_load_balancer_https.arn
    type = "forward"
  }

  depends_on = [
    aws_alb.load_balancer,
    aws_alb_target_group.tg_load_balancer_https
  ]
}


# We create a security group for our mysql instance
resource "aws_security_group" "sg_mysql" {
  depends_on = [
    aws_vpc.vpc,
  ]
  name        = "sg mysql"
  description = "Allow mysql inbound traffic"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    description = "allow TCP"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    security_groups = [aws_security_group.security_group_wordpress.id]
  }

  ingress {
    description = "allow SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${aws_eip.bastion_elastic_ip_1.public_ip}/32", "${aws_eip.bastion_elastic_ip_2.public_ip}/32"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# We create our mysql instance in the private subnet
resource "aws_instance" "mysql" {
  depends_on = [
    aws_security_group.sg_mysql,
    aws_nat_gateway.nat_gateway_1,
    aws_route_table_association.associate_routetable_to_private_subnet_1,
  ]
  ami = "ami-077e31c4939f6a2f3"
  instance_type = "t2.micro"
  key_name = aws_key_pair.public_ssh_key.key_name
  vpc_security_group_ids = [aws_security_group.sg_mysql.id]
  subnet_id = aws_subnet.private_subnet_1.id
  user_data = file("configure_mysql.sh")
  tags = {
      Name = "mysql-instance"
  }
}


# We create a security group for our wordpress instance
resource "aws_security_group" "security_group_wordpress" {
  depends_on = [
    aws_vpc.vpc,
  ]

  name        = "security-group-wordpress"
  description = "Allow http inbound traffic"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    description = "allow TCP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.public_subnet_1_CIDR, var.public_subnet_2_CIDR]   
  }
   
  ingress {
    description = "allow TCP"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.public_subnet_1_CIDR, var.public_subnet_2_CIDR]   
  } 
   
  ingress {
    description = "allow TCP"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
   
  ingress {
    description = "allow SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${aws_eip.bastion_elastic_ip_1.public_ip}/32", "${aws_eip.bastion_elastic_ip_2.public_ip}/32"] 
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}


resource "aws_launch_configuration" "wordpress_instance" {
  name_prefix   = "wordpress-instance-"
  image_id      = var.ec2_ami
  instance_type = var.ec2_type
  key_name      = aws_key_pair.public_ssh_key.key_name
  security_groups = [aws_security_group.security_group_wordpress.id]

   user_data = <<EOF
            #! /bin/bash
            yum update
            yum install docker -y
            systemctl restart docker
            systemctl enable docker
            docker pull wordpress
            docker run --name wordpress -p 80:80 -p 443:443 -e WORDPRESS_DB_HOST=${aws_instance.mysql.private_ip} \
            -e WORDPRESS_DB_USER=root -e WORDPRESS_DB_PASSWORD=root -e WORDPRESS_DB_NAME=wordpressdb -d wordpress
  EOF


  lifecycle {
    create_before_destroy = true
  }

  depends_on = [
    aws_security_group.security_group_wordpress
  ]
}

resource "aws_autoscaling_group" "auto_scaling_wordpress_az_1" {
  name                 = "auto-scaling-wordpress-az-1"
  launch_configuration = aws_launch_configuration.wordpress_instance.name
  min_size             = 1
  max_size             = 3
  vpc_zone_identifier       = [aws_subnet.private_subnet_1.id]
  target_group_arns         = [aws_alb_target_group.tg_load_balancer_http.arn, aws_alb_target_group.tg_load_balancer_https.arn]

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [
    aws_launch_configuration.wordpress_instance,
    aws_subnet.private_subnet_1,
    aws_alb_target_group.tg_load_balancer_http,
    aws_alb_target_group.tg_load_balancer_https 
  ]
}

resource "aws_autoscaling_group" "auto_scaling_wordpress_az_2" {
  name                 = "auto-scaling-wordpress-az-2"
  launch_configuration = aws_launch_configuration.wordpress_instance.name
  min_size             = 1
  max_size             = 3
  vpc_zone_identifier       = [aws_subnet.private_subnet_2.id]
  target_group_arns         = [aws_alb_target_group.tg_load_balancer_http.arn, aws_alb_target_group.tg_load_balancer_https.arn]

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [
    aws_launch_configuration.wordpress_instance,
    aws_subnet.private_subnet_2,
    aws_alb_target_group.tg_load_balancer_http,
    aws_alb_target_group.tg_load_balancer_https
  ]
}
