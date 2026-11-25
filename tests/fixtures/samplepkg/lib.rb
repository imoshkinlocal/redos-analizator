# Fixture: Ruby Onigmo use-site with request data.
VULN = /\A(a|aa)+\z/

def handle(params)
  params[:q] =~ VULN
end
