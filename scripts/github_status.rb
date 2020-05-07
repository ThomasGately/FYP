require 'sinatra'
require 'json'
require 'octokit'

post '/event_handler' do
	@payload = JSON.parse(params[:payload])

	case request.env['HTTP_X_GITHUB_EVENT']
	when "pull_request"
		process_pull_request(@payload["pull_request"])
	end
end

def process_pull_request(pull_request)
	@client.create_status(pull_request['base']['repo']['full_name'], pull_request['head']['sha'], 'pending', {context: "tests"})
	reslut = %x(./build/central_server.out)
	puts reslut
	if(reslut == "")  
		@client.create_status(pull_request['base']['repo']['full_name'], pull_request['head']['sha'], 'success', {context: "tests"})
	else  
		@client.create_status(pull_request['base']['repo']['full_name'], pull_request['head']['sha'], 'failure', {context: "tests"})
	end  
	puts "Pull request processed!"
end

before do
	@client ||= Octokit::Client.new(:access_token => "c47543e4fbf5600e3d8114f5188cadd173827de1")
end
