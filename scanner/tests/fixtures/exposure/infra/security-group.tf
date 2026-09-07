resource "aws_security_group" "public_gateway_sg" {
  name        = "public-gateway-sg"
  description = "Security group for public API gateway"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    description = "HTTP (redirect to HTTPS)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "public-gateway-sg"
    Environment = "production"
    Service     = "public-gateway"
  }
}

resource "aws_lb_target_group" "public_gateway" {
  name     = "public-gateway-tg"
  port     = 3000
  protocol = "HTTP"
  vpc_id   = var.vpc_id
}
