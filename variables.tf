variable "aws_region" {
  description = "The AWS region to create our infrastructure"
  default     = "us-east-2"
}

variable "AZ_1" {
  description = "Availability zone 1"
  default = "use2-az1"
}

variable "AZ_2" {
  description = "Availability zone 2"
  default = "use2-az2"
}

variable "ec2_type" {
  description = "The type of ec2 instances to create"
  default = "t2.micro"
}

variable "website-domain" {
  description = "Root domain"
  type        = string
  default     = "chatsfeed.com"
}

variable "www-website-domain" {
  description = "Main website domain"
  type        = string
  default     = "www.chatsfeed.com"
}

variable "app-website-domain" {
  description = "Portal website domain"
  type        = string
  default     = "app.chatsfeed.com"
}

variable "ec2_ami" {
  description = "The ubuntu 20.04 ami image to use for ec2 instances"
  default = "ami-0e5e17317f99b2932" 
}

variable "access_key" {
  type        = string
  default     = ""
}

variable "secret_key" {
  type        = string
  default     = ""
}

variable "vpc_cidr" {
  description = "VPC CIDR"
  default = "192.168.0.0/16"
}

variable "public_subnet_1_CIDR" {
  description = "Public Subnet 1 AZ 1 CIDR"
  default = "192.168.1.0/24"
}

variable "public_subnet_2_CIDR" {
  description = "Public Subnet 2 AZ 2 CIDR"
  default = "192.168.2.0/24"
}

variable "private_subnet_1_CIDR" {
  description = "Private Subnet 1 AZ 1 CIDR"
  default = "192.168.10.0/24"
}

variable "private_subnet_2_CIDR" {
  description = "Private Subnet 2 AZ 2 CIDR"
  default = "192.168.20.0/24"
}

variable "public_key_name" {
  type        = string
  default     = "ssh_public_key"
}

variable "private_key_name" {
  type        = string
  default     = "ssh_private_key"
}

variable "key_path" {
  type        = string
  default     = "/var/lib/jenkins/.ssh/"
}

variable "tags" {
  description = "Tags added to resources"
  default     = {}
  type        = map(string)
}
