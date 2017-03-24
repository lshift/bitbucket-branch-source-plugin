/*
 * The MIT License
 *
 * Copyright (c) 2016 CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

package com.cloudbees.jenkins.plugins.bitbucket.server.client.pullrequest;

import com.cloudbees.jenkins.plugins.bitbucket.api.BitbucketBranch;
import com.cloudbees.jenkins.plugins.bitbucket.api.BitbucketCommit;
import com.cloudbees.jenkins.plugins.bitbucket.api.BitbucketPullRequestDestination;
import com.cloudbees.jenkins.plugins.bitbucket.api.BitbucketPullRequestSource;
import com.cloudbees.jenkins.plugins.bitbucket.api.BitbucketRepository;
import com.cloudbees.jenkins.plugins.bitbucket.server.client.branch.BitbucketServerBranch;
import com.cloudbees.jenkins.plugins.bitbucket.server.client.branch.BitbucketServerCommit;
import com.cloudbees.jenkins.plugins.bitbucket.server.client.repository.BitbucketServerRepository;
import org.codehaus.jackson.annotate.JsonIgnoreProperties;
import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.annotate.JsonSetter;

@JsonIgnoreProperties(ignoreUnknown = true)
public class BitbucketServerPullRequestDestination implements BitbucketPullRequestDestination {

    @JsonProperty("latestCommit")
    private String commitHash;

    @JsonProperty("displayId")
    private String branchName;

    private BitbucketServerRepository repository;

    @JsonProperty
    private BitbucketServerCommit commit;

    @Override
    public BitbucketRepository getRepository() {
        return repository;
    }

    @Override
    @JsonProperty
    public BitbucketBranch getBranch() {
        return new BitbucketServerBranch(branchName, getLatestCommit());
    }

    @Override
    public BitbucketCommit getCommit() {
        return commit;
    }

    @JsonProperty
    public void setBranch(BitbucketServerBranch branch) {
        branchName = branch == null ? null : branch.getName();
    }

    public String getLatestCommit() {
        return commit == null ? null : commit.getHash();
    }

    @JsonProperty
    public void setLatestCommit(String latestCommit) {
        this.commit = new BitbucketServerCommit(latestCommit);
    }

    public void setBranchName(String branchName) {
        this.branchName = branchName;
    }
    
    public void setRepository(BitbucketServerRepository repository) {
        this.repository = repository;
    }

    public String getCommitHash(){
        return commitHash;
    }
}
