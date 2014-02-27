require 'net/ldap'

module LdapClient
  LdapNotEnabled = Class.new(StandardError)
  LdapNotCorrectlyConfigured = Class.new(StandardError)
  extend self

  def enabled?
    config.fetch('enable', false)
  end

  # used to prefill a user create form
  def search(username)
    filter = Net::LDAP::Filter.eq(config['attribute']['uid'], username)
    results = client.search :filter => filter

    unless results
      error = client.get_operation_result
      Rails.logger.error "LDAP Error: Code: #{error.code} Message: #{error.message}"
      raise LdapNotCorrectlyConfigured.new(error.message)
    end

    results.map do |result|
      {
        :username =>   result[config['attribute']['uid']].first,
        :dept =>       result[config['attribute']['ou']].first,
        :first_name => result[config['attribute']['gn']].first,
        :last_name =>  result[config['attribute']['sn']].first,
        :email =>      result[config['attribute']['mail']].first,
        :title =>      result[config['attribute']['title']].first
      }
    end
  end

  # used to login to Chorus as an LDAP user
  def authenticate(username, password)
    ldap = client
    ldap.auth make_dn(username), password
    ldap.bind
  end

  def client
    raise LdapNotEnabled.new unless enabled?
    ldap_args = {:host => config['host'], :port => config['port'], :base => config['base'], :auth => {:method => :anonymous}}
    if config['user_dn'].present?
      ldap_args[:auth] = {:method => :simple, :username => config['user_dn'], :password => config['password']}
    end
    if config['start_tls'].present?
      ldap_args[:encryption] = :start_tls
    end
    Net::LDAP.new ldap_args
  end

  private

  def make_dn(username)
    config['dn_template'].gsub('{0}', username)
  end

  def config
    ChorusConfig.instance['ldap'] || {}
  end
end
