resource "aws_iam_instance_profile" "controller" {
  name_prefix = "tf-${var.cluster_name}-controller"
  role        = "${aws_iam_role.controller.name}"
}

resource "aws_iam_instance_profile" "worker" {
  name_prefix = "tf-${var.cluster_name}-worker"
  role        = "${aws_iam_role.worker.name}"
}

resource "aws_iam_role" "controller" {
  name = "tf-${var.cluster_name}-controllerRole"
  path = "/"

  assume_role_policy = "${data.aws_iam_policy_document.ec2_service_policy.json}"
}

resource "aws_iam_role" "worker" {
  name = "tf-${var.cluster_name}-workerRole"
  path = "/"

  assume_role_policy = "${data.aws_iam_policy_document.ec2_service_policy.json}"
}

resource "aws_iam_role_policy" "controller_policy" {
  name = "tf-${var.cluster_name}-controllerPolicy"

  role = "${aws_iam_role.controller.id}"

  policy = "${data.aws_iam_policy_document.controller_policy.json}"
}

resource "aws_iam_role_policy" "worker_policy" {
  name = "tf-${var.cluster_name}-workerPolicy"

  role = "${aws_iam_role.worker.id}"

  policy = "${data.aws_iam_policy_document.worker_policy.json}"
}

data "aws_iam_policy_document" "ec2_service_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# based on https://github.com/kubernetes/kops/blob/master/docs/iam_roles.md
data "aws_iam_policy_document" "controller_policy" {
  statement {
    sid = "EC2MasterPermsDescribeResources"

    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeRegions",
      "ec2:DescribeRouteTables",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSubnets",
      "ec2:DescribeVolumes",
    ]

    resources = [
      "*",
    ]
  }

  statement {
    sid = "EC2MasterPermsAllResources"

    actions = [
      "ec2:CreateSecurityGroup",
      "ec2:CreateTags",
      "ec2:CreateVolume",
      "ec2:ModifyInstanceAttribute",
    ]

    resources = [
      "*",
    ]
  }

  statement {
    sid = "EC2MasterPermsTaggedResources"

    actions = [
      "ec2:AttachVolume",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:CreateRoute",
      "ec2:DeleteRoute",
      "ec2:DeleteSecurityGroup",
      "ec2:DeleteVolume",
      "ec2:DetachVolume",
      "ec2:RevokeSecurityGroupIngress",
    ]

    resources = [
      "*",
    ]

    condition {
      test     = "StringEquals"
      variable = "ec2:ResourceTag/kubernetes.io/cluster/${local.fqdn}"

      values = [
        "owned",
        "shared",
        "true",
      ]
    }
  }

  statement {
    sid = "ASMasterPermsAllResources"

    actions = [
      "autoscaling:DescribeAutoScalingGroups",
      "autoscaling:DescribeLaunchConfigurations",
      "autoscaling:DescribeTags",
      "autoscaling:GetAsgForInstance",
    ]

    resources = [
      "*",
    ]
  }

  statement {
    sid = "ASMasterPermsTaggedResources"

    actions = [
      "autoscaling:SetDesiredCapacity",
      "autoscaling:TerminateInstanceInAutoScalingGroup",
      "autoscaling:UpdateAutoScalingGroup",
    ]

    resources = [
      "*",
    ]

    condition {
      test     = "StringEquals"
      variable = "autoscaling:ResourceTag/kubernetes.io/cluster/${local.fqdn}"

      values = [
        "owned",
        "shared",
        "true",
      ]
    }
  }

  statement {
    sid = "ELBMasterPermsRestrictive"

    actions = [
      "elasticloadbalancing:AddTags",
      "elasticloadbalancing:AttachLoadBalancerToSubnets",
      "elasticloadbalancing:ApplySecurityGroupsToLoadBalancer",
      "elasticloadbalancing:CreateLoadBalancer",
      "elasticloadbalancing:CreateLoadBalancerPolicy",
      "elasticloadbalancing:CreateLoadBalancerListeners",
      "elasticloadbalancing:ConfigureHealthCheck",
      "elasticloadbalancing:DeleteLoadBalancer",
      "elasticloadbalancing:DeleteLoadBalancerListeners",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeLoadBalancerAttributes",
      "elasticloadbalancing:DetachLoadBalancerFromSubnets",
      "elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
      "elasticloadbalancing:ModifyLoadBalancerAttributes",
      "elasticloadbalancing:RegisterInstancesWithLoadBalancer",
      "elasticloadbalancing:SetLoadBalancerPoliciesForBackendServer",
    ]

    resources = [
      "*",
    ]
  }

  statement {
    sid = "NLBMasterPermsRestrictive"

    actions = [
      "ec2:DescribeVpcs",
      "elasticloadbalancing:AddTags",
      "elasticloadbalancing:CreateListener",
      "elasticloadbalancing:CreateTargetGroup",
      "elasticloadbalancing:DeleteListener",
      "elasticloadbalancing:DeleteTargetGroup",
      "elasticloadbalancing:DescribeListeners",
      "elasticloadbalancing:DescribeLoadBalancerPolicies",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeTargetHealth",
      "elasticloadbalancing:ModifyListener",
      "elasticloadbalancing:ModifyTargetGroup",
      "elasticloadbalancing:RegisterTargets",
      "elasticloadbalancing:SetLoadBalancerPoliciesOfListener",
    ]

    resources = [
      "*",
    ]
  }

  statement {
    sid = "MasterCertIAMPerms"

    actions = [
      "iam:ListServerCertificates",
      "iam:GetServerCertificate",
    ]

    resources = [
      "*",
    ]
  }
}

# Originally based on the kops permissions, this matches also: https://github.com/kubernetes/cloud-provider-aws
data "aws_iam_policy_document" "worker_policy" {
  statement {
    sid = "EC2NodePerms"

    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeRegions",
    ]

    resources = [
      "*",
    ]
  }

  statement {
    sid = "WorkerECRReadOnly"

    actions = [
      "ecr:GetAuthorizationToken",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:GetRepositoryPolicy",
      "ecr:DescribeRepositories",
      "ecr:ListImages",
      "ecr:BatchGetImage",
    ]

    resources = [
      "*",
    ]
  }
}
