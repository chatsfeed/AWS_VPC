
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
    bucket         = "chatsfeed-terraform-s3-remote-state"
    key            = "terraform.tfstate"
    region  = "us-east-2"
    # Replace this with your DynamoDB table name!
    dynamodb_table = "chatsfeed-terraform-dynamodb-remote-state-locks"
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

# Creates the DNS record to point on the main CloudFront distribution ID
resource "aws_route53_record" "website_cdn_root_record" {
  #zone_id = data.aws_route53_zone.wildcard_website.zone_id
  zone_id = "${aws_route53_zone.main.zone_id}"
  name    = var.website-domain
  type    = "A"

  alias {
    name = aws_alb.load_balancer.dns_name   #aws_cloudfront_distribution.website_cdn_root.domain_name
    zone_id = aws_alb.load_balancer.zone_id   #aws_cloudfront_distribution.website_cdn_root.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "www_cname_route53_record" {
  zone_id = aws_route53_zone.main.zone_id # Replace with your zone ID
  name    = "www.chatsfeed.com" # Replace with your subdomain, Note: not valid with "apex" domains, e.g. example.com
  type    = "CNAME"
  ttl     = "60"
  records = [aws_alb.load_balancer.dns_name]   #[aws_cloudfront_distribution.website_cdn_root.domain_name] #[aws_alb.load_balancer.dns_name]
}


resource "aws_route53_record" "app_cname_route53_record" {
  zone_id = aws_route53_zone.main.zone_id # Replace with your zone ID
  name    = "app.chatsfeed.com" # Replace with your subdomain, Note: not valid with "apex" domains, e.g. example.com
  type    = "CNAME"
  ttl     = "60"
  records = [aws_alb.load_balancer.dns_name]     #[aws_cloudfront_distribution.website_cdn_root.domain_name] #[aws_alb.load_balancer.dns_name]
}


resource "aws_route53_record" "domain_mx_record" {
  zone_id = aws_route53_zone.main.zone_id
  name    = "domain-mx-record"
  type    = "MX"
  
  records = [
    "1 ASPMX.L.GOOGLE.COM",
    "5 ALT1.ASPMX.L.GOOGLE.COM",
    "5 ALT2.ASPMX.L.GOOGLE.COM",
    "10 ASPMX2.GOOGLEMAIL.COM",
    "10 ASPMX3.GOOGLEMAIL.COM",  
  ]
  
  ttl = "3600"
}

resource "aws_iam_user" "smtp_user" {
  name = "smtp_user"
}

resource "aws_iam_access_key" "smtp_user" {
  user = aws_iam_user.smtp_user.name
}

data "aws_iam_policy_document" "ses_sender" {
  statement {
    actions   = ["ses:SendRawEmail"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "ses_sender" {
  name        = "ses_sender"
  description = "Allows sending of e-mails via Simple Email Service"
  policy      = data.aws_iam_policy_document.ses_sender.json
}

resource "aws_iam_user_policy_attachment" "test-attach" {
  user       = aws_iam_user.smtp_user.name
  policy_arn = aws_iam_policy.ses_sender.arn
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
resource "aws_alb_target_group" "tg_load_balancer_http_app" {
  name     = "tg-load-balancer-http-app"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.vpc.id

  depends_on = [
    aws_vpc.vpc
  ]
}

resource "aws_alb_target_group" "tg_load_balancer_http_www" {
  name     = "tg-load-balancer-http-www"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.vpc.id

  depends_on = [
    aws_vpc.vpc
  ]
}



resource "aws_alb_target_group" "tg_load_balancer_https_app" {
  name     = "tg-load-balancer-https-app"
  port     = 443
  protocol = "HTTPS"
  #port              = "80"
  #protocol          = "HTTP"   
  vpc_id   = aws_vpc.vpc.id

  depends_on = [
    aws_vpc.vpc
  ]
}

resource "aws_alb_target_group" "tg_load_balancer_https_www" {
  name     = "tg-load-balancer-https-www"
  port     = 443
  protocol = "HTTPS"
  #port              = "80"
  #protocol          = "HTTP"   
  vpc_id   = aws_vpc.vpc.id

  depends_on = [
    aws_vpc.vpc
  ]
}


# Create a new ALB Target Group attachment
resource "aws_alb_target_group_attachment" "tg_load_balancer_attachement_http_app" {
  target_group_arn = aws_alb_target_group.tg_load_balancer_http_app.arn
  target_id        = aws_instance.app.id
  port             = 80
}

resource "aws_alb_target_group_attachment" "tg_load_balancer_attachement_https_app" {
  target_group_arn = aws_alb_target_group.tg_load_balancer_https_app.arn
  target_id        = aws_instance.app.id
  port             = 443
}


resource "aws_alb_target_group_attachment" "tg_load_balancer_attachement_http_www" {
  target_group_arn = aws_alb_target_group.tg_load_balancer_http_www.arn
  target_id        = aws_instance.www.id
  port             = 80
}

resource "aws_alb_target_group_attachment" "tg_load_balancer_attachement_https_www" {
  target_group_arn = aws_alb_target_group.tg_load_balancer_https_www.arn
  target_id        = aws_instance.www.id
  port             = 443
}


# We create our application load balancer
resource "aws_alb" "load_balancer" {
  name               = "load-balancer"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.sg_load_balancer.id]
  subnets            = [aws_subnet.public_subnet_1.id, aws_subnet.public_subnet_2.id]

  enable_deletion_protection = false
  
  #getting s3 permission issues 
  #access_logs {
    #bucket  = aws_s3_bucket.website_logs.bucket
    #prefix  = "load-balancer-logs"
    #enabled = true
  #} 

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
  load_balancer_arn = aws_alb.load_balancer.arn
  port              = "80"
  protocol          = "HTTP"
  
  #default_action {
  #  type = "redirect"

  #  redirect {
  #    port        = "443"
  #    protocol    = "HTTPS"
  #    status_code = "HTTP_301"
  #  }
  #}
   
  default_action {
    type             = "forward"
    forward {
    #1 to 5 target_group 
    target_group {
        arn = aws_alb_target_group.tg_load_balancer_http_app.arn
    }
    target_group {
        arn = aws_alb_target_group.tg_load_balancer_http_www.arn
    }
   }
  }
   
  depends_on = [
    aws_alb.load_balancer
    #aws_alb_target_group.tg_load_balancer_http_app
  ]
}



resource "aws_alb_listener_rule" "listener_load_balancer_rule_http" {
  depends_on   = [aws_alb_target_group.tg_load_balancer_http_www]  
  listener_arn = aws_alb_listener.listener_load_balancer_http.arn
  #priority     = 100   
  action {    
    type             = "forward"    
    target_group_arn = "${aws_alb_target_group.tg_load_balancer_http_www.id}"  
  }  
   
  condition {
    host_header {
      values = ["${var.www-website-domain}"]
    }
  } 
   

}


resource "aws_alb_listener_rule" "listener_load_balancer_rule_root_http" {
  depends_on   = [aws_alb_target_group.tg_load_balancer_http_www]  
  listener_arn = aws_alb_listener.listener_load_balancer_http.arn
  #priority     = 100   
  action {    
    type             = "forward"    
    target_group_arn = "${aws_alb_target_group.tg_load_balancer_http_www.id}"  
  }  
   
  condition {
    host_header {
      values = ["${var.website-domain}"]
    }
  } 
   
}



resource "aws_alb_listener_rule" "listener_load_balancer_rule_app_http" {
  depends_on   = [aws_alb_target_group.tg_load_balancer_http_app]  
  listener_arn = aws_alb_listener.listener_load_balancer_http.arn
  #priority     = 100   
  action {    
    type             = "forward"    
    target_group_arn = "${aws_alb_target_group.tg_load_balancer_http_app.id}"  
  }  
   
  condition {
    host_header {
      values = ["${var.app-website-domain}"]
    }
  } 
   
   
}



# NB: CloudFront requires the ACM certificate be in us-east-1 region. 
# But ALB requires that the cert be in the same region as the ALB. 
# We'll have to create an ACM certificate again for ALB.

resource "aws_acm_certificate" "wildcard_website_alb" {
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

  lifecycle {
    ignore_changes = [tags["Changed"]]
  }

}

resource "aws_acm_certificate_validation" "wildcard_cert_alb" {
  certificate_arn         = aws_acm_certificate.wildcard_website_alb.arn
}


data "aws_acm_certificate" "wildcard_website_alb" {
  depends_on = [
    aws_acm_certificate.wildcard_website_alb,
    aws_acm_certificate_validation.wildcard_cert_alb,
  ]

  domain      = "*.${var.website-domain}" 
  statuses    = ["ISSUED"]
  most_recent = true
}



# We create an https listener for our application load balancer
resource "aws_alb_listener" "listener_load_balancer_https" {
  load_balancer_arn = aws_alb.load_balancer.arn
  port              = "443"
  protocol          = "HTTPS"
  
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  # Default certificate
  certificate_arn   = data.aws_acm_certificate.wildcard_website_alb.arn
   
  default_action {
    type             = "forward"
    forward {
    # 1 to 5 target_group 
    target_group {
        arn = aws_alb_target_group.tg_load_balancer_https_app.arn
    }
    target_group {
        arn = aws_alb_target_group.tg_load_balancer_https_www.arn
    }
   }
  }

  depends_on = [
    aws_alb.load_balancer
    #aws_alb_target_group.tg_load_balancer_https_www
  ]
}


resource "aws_alb_listener_rule" "listener_load_balancer_rule_https" {
  depends_on   = [aws_alb_target_group.tg_load_balancer_https_www]  
  listener_arn = aws_alb_listener.listener_load_balancer_https.arn
  #priority     = 100   
  action {    
    type             = "forward"    
    target_group_arn = "${aws_alb_target_group.tg_load_balancer_https_www.id}"  
  }  
   
  condition {
    host_header {
      values = ["${var.www-website-domain}"]
    }
  } 
   

}


resource "aws_alb_listener_rule" "listener_load_balancer_rule_root_https" {
  depends_on   = [aws_alb_target_group.tg_load_balancer_https_www]  
  listener_arn = aws_alb_listener.listener_load_balancer_https.arn
  #priority     = 100   
  action {    
    type             = "forward"    
    target_group_arn = "${aws_alb_target_group.tg_load_balancer_https_www.id}"  
  }  
   
  condition {
    host_header {
      values = ["${var.website-domain}"]
    }
  } 
   
}



resource "aws_alb_listener_rule" "listener_load_balancer_rule_app_https" {
  depends_on   = [aws_alb_target_group.tg_load_balancer_https_app]  
  listener_arn = aws_alb_listener.listener_load_balancer_https.arn
  #priority     = 100   
  action {    
    type             = "forward"    
    target_group_arn = "${aws_alb_target_group.tg_load_balancer_https_app.id}"  
  }  
   
  condition {
    host_header {
      values = ["${var.app-website-domain}"]
    }
  } 
   
   
}




# We create our www instance in public subnet
resource "aws_instance" "app" {
  depends_on = [
    aws_security_group.sg_app
  ]
  ami = var.ec2_ami  #"ami-077e31c4939f6a2f3"
  instance_type = "t2.medium"
  key_name = aws_key_pair.public_ssh_key.key_name
  vpc_security_group_ids = [aws_security_group.sg_app.id]
  subnet_id = aws_subnet.public_subnet_1.id

  tags = {
      Name = "app"
  }
}


# We create our www instance in public subnet
resource "aws_instance" "www" {
  depends_on = [
    aws_security_group.sg_www
  ]
  ami = var.ec2_ami  #"ami-077e31c4939f6a2f3"
  instance_type = "t2.micro"
  key_name = aws_key_pair.public_ssh_key.key_name
  vpc_security_group_ids = [aws_security_group.sg_www.id]
  subnet_id = aws_subnet.public_subnet_1.id

  tags = {
      Name = "www"
  }
}



# We create a security group for our app instance
resource "aws_security_group" "sg_app" {
  depends_on = [
    aws_vpc.vpc,
  ]

  name        = "sg app"
  description = "Allow http inbound traffic"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    description = "allow TCP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  } 
  ingress {
    description = "allow TCP"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  } 
  ingress {
    description = "allow TCP"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }   
  ingress {
    description = "allow SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] 
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}





# We create a security group for our www instance
resource "aws_security_group" "sg_www" {
  depends_on = [
    aws_vpc.vpc,
  ]

  name        = "sg www"
  description = "Allow http inbound traffic"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    description = "allow TCP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "allow TCP"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }   
  ingress {
    description = "allow SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] 
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}








