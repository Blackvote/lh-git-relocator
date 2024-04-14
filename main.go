package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/go-git/go-git/v5"
	"github.com/google/go-github/v37/github"
	"github.com/manifoldco/promptui"
	"github.com/pkg/errors"
	"github.com/spf13/cast"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/xanzy/go-gitlab"
	"golang.org/x/crypto/nacl/box"
	"gopkg.in/yaml.v3"
	"io"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	finalGitDir      = ".git"
	configFileName   = "gl-migrator-cfg"
	logFileName      = "migratorLogfile.log"
	progressFileName = "progress.json"
)

var (
	ghToken, // Токены
	glToken string // Для передачи в Push\Pull
	state,
	isRateLimitExceeded bool
	processedPrID int
)

type ProjectInfo struct {
	ProjectID     int                `json:"project_id"`
	MergeRequests []MergeRequestInfo `json:"merge_requests"`
}

type MergeRequestInfo struct {
	MergeRequestID int `json:"merge_request_id"`
	StatusCode     int `json:"status_code"`
}

type Config struct {
	Repo           RepoConfig        `yaml:"repo"`
	SecretMap      map[string]string `yaml:"secret"`
	SecretOnlyMode string            `yaml:"secretOnlyMode"`
}

type RepoConfig struct {
	Source       string `yaml:"source"`
	Organization string `yaml:"organization"`
	RepoName     string `yaml:"repoName"`
	Topics       string `yaml:"topics"`
}

var rootCmd = &cobra.Command{
	Use:   "gl-migrator",
	Short: "migrate GL repo to GH",
	Run: func(cmd *cobra.Command, args []string) {

		dir, err := os.Getwd()
		//usr, err := user.Current()
		if err != nil {
			panic(err)
		}

		logFilePath := filepath.Join(logFileName)
		// Открываем или создаем файл логов для добавления записей
		logFile, err := os.OpenFile(logFilePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			log.Fatal("Unable to create log file: ", err)
		}

		defer func(logFile *os.File) {
			err := logFile.Close()
			if err != nil {
			}
		}(logFile)

		multiWriter := io.MultiWriter(logFile, os.Stdout)

		// Настройка библиотеки log для записи логов в мультирайтер
		log.SetOutput(multiWriter)
		log.Println("Application start:", time.Now())

		// Загрузка конфигурации из файла
		config, err := loadConfig("config.yml")
		if err != nil {
			fmt.Printf("Ошибка при загрузке конфигурации: %v\n", err)
			os.Exit(1)
		}

		// Создание переменных из конфигурации
		sourceURL := config.Repo.Source
		organization := config.Repo.Organization
		repoName := config.Repo.RepoName
		topics := config.Repo.Topics
		secretOnlyMode := config.SecretOnlyMode

		if !strings.HasSuffix(sourceURL, ".git") {
			if !strings.HasSuffix(sourceURL, "/") {
				sourceURL += ".git"
			} else {
				sourceURL = sourceURL[:len(sourceURL)-1] + ".git"
			}
		}

		// Попытка получить state
		progressFilePath := filepath.Join(progressFileName)
		var processedMR map[int][]MergeRequestInfo
		if _, err := os.Stat(progressFilePath); err == nil {
			log.Printf("Progress file was found %s\nState:", progressFilePath)
			processedPrID, processedMR, err = readProcessedPullRequestsFromFile(progressFilePath)
			if err != nil {
				log.Printf("Can't validate progress file %s", err)
			}
			if processedMR != nil {
				// state = true только если смогли распарсить Json
				state = true
			} else {
				log.Println("State is empty.")
			}
		} else {
			log.Println("Progress file was not found")
		}

		mrTable := createMRTable(processedMR)
		for statusCode, count := range mrTable {
			fmt.Printf("Status Code %d: %d MR\n", statusCode, count)
		}

		_, err = url.ParseRequestURI(sourceURL)
		if err != nil {
			log.Fatalf("Source must be a valid URL %v", err)
		}

		// Конфигурация токенов
		viper.SetConfigName(configFileName)
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		if err := viper.ReadInConfig(); err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); ok {
				// Config file not found; ignore error if desired
			} else {
				panic(err)
			}
		}
		if viper.GetString("credentials.github.pat") == "" && ghToken == "" {
			viper.Set("credentials.github.pat", getPAT())
			if err := viper.WriteConfigAs(filepath.Join(configFileName + ".yaml")); err != nil {
				log.Println("Error while saving config: " + err.Error())
			}
		}
		if viper.GetString("credentials.gitlab.pat") == "" && glToken == "" {
			viper.Set("credentials.gitlab.pat", getGLToken())
			if err := viper.WriteConfigAs(filepath.Join(configFileName + ".yaml")); err != nil {
				log.Println("Error while saving config: " + err.Error())
			}
		}
		if ghToken == "" {
			ghToken = viper.GetString("credentials.github.pat")
		}
		if glToken == "" {
			glToken = viper.GetString("credentials.gitlab.pat")
		}

		// Разбираем Урл для получения информации о владельцах репы
		parsedURL, err := url.Parse(sourceURL)
		if err != nil {
			panic(err)
		}

		// Разбиваем путь на части по символу '/'
		pathParts := strings.Split(strings.Trim(parsedURL.Path, "/"), "/")

		// Проверяем, что путь содержит как минимум две части
		if len(pathParts) < 2 {
			panic("Invalid URL format")
		}

		// Извлекаем домен
		gitlabURL := parsedURL.Scheme + "://" + parsedURL.Host

		// Извлекаем группу и подгруппу репозитория
		var srcRepoGroup, srcSubgroup string
		if len(pathParts) > 2 {
			srcRepoGroup = pathParts[0]
			srcSubgroup = pathParts[1]
		} else {
			srcRepoGroup = pathParts[0]
		}
		_ = srcSubgroup
		// Извлекаем имя репозитория, удаляем расширение ".git"
		srcRepoName := strings.TrimSuffix(pathParts[len(pathParts)-1], ".git")

		// Делаем паузу, после каждого обращения к Gh, чтобы не забанило Get запросы
		duration := 5 * time.Second

		githubClient := getGitHubClient(ghToken)
		gitlabClient, err := gitlab.NewClient(glToken, gitlab.WithBaseURL(gitlabURL))

		if secretOnlyMode == "true" {

			existingRepo, _, err := githubClient.Repositories.Get(context.Background(), organization, repoName)
			if existingRepo == nil {
				log.Printf("Repository %s/%s is not exist. Exit", organization, repoName)
				return
			} else {
				log.Printf("Repository %s/%s Found", organization, repoName)
			}

			repoPublicKey, _, err := githubClient.Actions.GetRepoPublicKey(context.Background(), organization, repoName)
			if err != nil {
				return
			}

			for name, value := range config.SecretMap {
				encodedSecretValue, err := EncodeWithPublicKey(value, *repoPublicKey.Key)
				if err != nil {
					return
				}

				secret := &github.EncryptedSecret{
					Name:           name,
					KeyID:          *repoPublicKey.KeyID,
					EncryptedValue: encodedSecretValue,
				}

				_, err = githubClient.Actions.CreateOrUpdateRepoSecret(context.Background(), organization, repoName, secret)
				if err != nil {
					return
				}
				log.Printf("Secret \"%s\" update/create successfully", name)
			}
			return
		}

		// Создаём GitHub репо
		var GithubRepository *github.Repository
		existingRepo, _, err := githubClient.Repositories.Get(context.Background(), organization, repoName)

		if existingRepo == nil {
			GithubRepository, _, err = CreateGitHubRepository(githubClient, organization, repoName)
			if err != nil {
			}
			if topics != "" {
				topicList := strings.Split(topics, ",")
				err = AddTopicsToRepository(githubClient, GithubRepository, topicList)
				if err != nil {
					log.Fatal(err)
				}
			}
		} else {
			GithubRepository = existingRepo
		}

		destinationURL := cast.ToString(GithubRepository.HTMLURL)
		dstParts := strings.Split(destinationURL, "/")
		owner := dstParts[len(dstParts)-2]
		dstRepo := dstParts[len(dstParts)-1]
		dstRepo = strings.Replace(dstRepo, ".git", "", 1)

		// Получаем имя итоговой директории
		parts := strings.Split(sourceURL, "/")
		gitDir := parts[len(parts)-1]
		if err != nil {
			log.Println("Working dir setup error", err)
		}
		log.Printf("Working dir setup to: \"%s\"", dir)

		//
		repoPublicKey, _, err := githubClient.Actions.GetRepoPublicKey(context.Background(), organization, repoName)
		if err != nil {
			return
		}

		for name, value := range config.SecretMap {
			encodedSecretValue, err := EncodeWithPublicKey(value, *repoPublicKey.Key)
			if err != nil {
				return
			}

			secret := &github.EncryptedSecret{
				Name:           name,
				KeyID:          *repoPublicKey.KeyID,
				EncryptedValue: encodedSecretValue,
			}

			_, err = githubClient.Actions.CreateOrUpdateRepoSecret(context.Background(), organization, repoName, secret)
			if err != nil {
				return
			}
		}

		//
		removeRepo(dir)

		if strings.HasPrefix(sourceURL, "https://") {
			sourceURL = strings.Replace(sourceURL, "https://", "", 1)
		}

		log.Printf("Cloning Repo \"%s\"", sourceURL)
		clone := exec.Command("git", "clone", "--bare", "https://oauth2:"+glToken+"@"+sourceURL)
		output, err := clone.Output()
		if string(output) != "" {
			log.Println(string(output))
		}
		if err != nil {
			log.Fatalf("Failed to clone: %v", err)
		}

		if _, err := os.Stat(gitDir); os.IsNotExist(err) {
			gitDir = gitDir + ".git"
		}
		log.Printf("Renaming %v to %v", gitDir, finalGitDir)
		err = os.Rename(gitDir, finalGitDir)
		if err != nil {
			log.Fatalf("Failed to rename: %v", err)
		}

		// Получаем содержимое папки .git как набор параметров
		log.Println("Validate cloned repo")
		r, err := git.PlainOpen(".")
		if err != nil {
			log.Fatalf("Failed to open local repo: %v", err)
		}

		headRef, err := r.Head()
		if err != nil {
			log.Fatalf("HEAD getting error: %v\n", err)
		}
		newDefaultBranch := headRef.Name().Short()

		// Получаем конфиг репозитория
		cfg, err := r.Config()
		if err != nil {
			log.Fatalf("Failed to get repo config: %v", err)
		}

		// Получаем origin
		remote, ok := cfg.Remotes["origin"]
		if !ok {
			log.Fatal("Remote 'origin' not found")
		}

		log.Printf("Setting up origin-url from %v to %v\n", "https://"+sourceURL, destinationURL)
		// Меняем origin.url
		remote.URLs = []string{destinationURL}
		err = r.SetConfig(cfg)
		if err != nil {
			log.Fatalf("Failed to set remote: %v", err)
		}

		// Получаем PID
		log.Println("Getting remote repo PID")
		projectListOptions := &gitlab.ListProjectsOptions{
			ListOptions: gitlab.ListOptions{
				PerPage: 100, // 100 - доступный максимум
			},
			Search: &srcRepoName,
		}

		projects, _, err := gitlabClient.Projects.ListProjects(projectListOptions)
		if err != nil {
			log.Fatal(err)
		}
		if len(projects) == 0 {
			log.Fatal("Cant find any projects")
		}

		var projectID int

		if len(projects) > 1 {
			projectPathToSearch := strings.TrimSuffix(parsedURL.Path, ".git")
			projectPathToSearch = strings.TrimPrefix(projectPathToSearch, "/")
			for _, project := range projects {
				if project.PathWithNamespace == fmt.Sprintf("%s", projectPathToSearch) {
					projectID = project.ID
					break
				}
			}
		} else if len(projects) == 1 {
			projectID = projects[0].ID
		}
		log.Printf("PID = %d", projectID)

		if state && projectID != processedPrID {
			state = false
			log.Printf("ProjectID from source url (%d) and projectID from progress file (%d) does not match. Work without state", projectID, processedPrID)
		}

		log.Println("Pushing to origin")
		pushRepo(finalGitDir, ghToken)

		log.Printf("Setting default branch to %s\n", newDefaultBranch)
		_, _, err = githubClient.Repositories.Edit(context.Background(), owner, dstRepo, &github.Repository{
			DefaultBranch: &newDefaultBranch,
		})
		if err != nil {
			log.Fatal(err)
		}

		var allMergeRequests []*gitlab.MergeRequest
		getMrOption := &gitlab.ListProjectMergeRequestsOptions{
			ListOptions: gitlab.ListOptions{
				PerPage: 100, // 100 - доступный максимум
			},
		}

		var mergeRequestIDs403 []int
		if state {
			totalMr := 0
			for _, mrs := range processedMR {
				totalMr += len(mrs)
			}
			log.Printf("Found %d processed mr", totalMr)
			mergeRequestIDs403 = getMergeRequestIDsForStatusCode(processedMR, 403)
			if len(mergeRequestIDs403) == 0 {
				state = false
				log.Println("Not found any 403 error code")
			} else {
				log.Printf("%d mr have 403 status code", len(mergeRequestIDs403))
			}
		}
		for {
			mergeRequests, response, err := gitlabClient.MergeRequests.ListProjectMergeRequests(projectID, getMrOption)
			if err != nil {
				log.Fatal(err)
			}
			if state {
				for _, mergeRequest := range mergeRequests {
					for _, mrID := range mergeRequestIDs403 {
						if mergeRequest.IID == mrID {
							allMergeRequests = append(allMergeRequests, mergeRequest)
						}
					}
				}
			} else {
				allMergeRequests = append(allMergeRequests, mergeRequests...)
			}

			if response.CurrentPage >= response.TotalPages {
				break
			}

			getMrOption.Page = response.NextPage
		}

		log.Printf("Will migrate %d merge requests", len(allMergeRequests))

		var allExistingPullRequests []*github.PullRequest
		pullRequestOption := &github.PullRequestListOptions{
			State: "all",
			ListOptions: github.ListOptions{
				PerPage: 10,
			}}

		for {
			existingPullRequests, response, err := githubClient.PullRequests.List(context.Background(), owner, dstRepo, pullRequestOption)
			if err != nil {
				log.Fatal(err)
			}
			allExistingPullRequests = append(allExistingPullRequests, existingPullRequests...)

			if response.NextPage == 0 {
				break
			}

			pullRequestOption.Page = response.NextPage
			time.Sleep(duration)
		}
		processedPullRequests := make(map[string]bool)
		for _, pr := range allExistingPullRequests {
			processedPullRequests[pr.GetTitle()] = true
		}

		projectInfo := ProjectInfo{
			ProjectID:     projectID,
			MergeRequests: []MergeRequestInfo{},
		}

		// Сортируем MR по возрастанию (chat.openai.com)
		sort.Slice(allMergeRequests, func(i, j int) bool {
			return allMergeRequests[i].IID < allMergeRequests[j].IID
		})

		//Создание PR
		for _, mergeRequest := range allMergeRequests {
			if processedPullRequests[mergeRequest.Title] {
				log.Printf("Merge request \"%s\" already exist. Skip it.\n", mergeRequest.Title)
				mergeRequestInfo := MergeRequestInfo{
					MergeRequestID: mergeRequest.IID,
					StatusCode:     200,
				}
				projectInfo.MergeRequests = append(projectInfo.MergeRequests, mergeRequestInfo)
				continue
			}
			log.Printf("Merge request \"%s\" Not Exist. Cheking branch...\n", mergeRequest.Title)
			_, resp, err := githubClient.Repositories.GetBranch(context.Background(), owner, dstRepo, mergeRequest.SourceBranch, false)
			if resp.StatusCode == 404 {
				log.Printf("Cannot create PR. Source branch(%s) does not exist\n", mergeRequest.SourceBranch)
				mergeRequestInfo := MergeRequestInfo{
					MergeRequestID: mergeRequest.IID,
					StatusCode:     404,
				}
				projectInfo.MergeRequests = append(projectInfo.MergeRequests, mergeRequestInfo)
				continue
			} else if err != nil {
				log.Printf("Cannot get Source branch. Does it exist? (%s)\n", mergeRequest.SourceBranch)
				mergeRequestInfo := MergeRequestInfo{
					MergeRequestID: mergeRequest.IID,
					StatusCode:     404,
				}
				projectInfo.MergeRequests = append(projectInfo.MergeRequests, mergeRequestInfo)
				continue
			}

			_, resp, err = githubClient.Repositories.GetBranch(context.Background(), owner, dstRepo, mergeRequest.TargetBranch, false)
			if resp.StatusCode == 404 {
				log.Printf("Cannot create PR. Target branch(%s) does not exist\n", mergeRequest.TargetBranch)
				mergeRequestInfo := MergeRequestInfo{
					MergeRequestID: mergeRequest.IID,
					StatusCode:     404,
				}
				projectInfo.MergeRequests = append(projectInfo.MergeRequests, mergeRequestInfo)
				continue
			} else if err != nil {
				log.Printf("Cannot get Target branch. Does it exist? (%s)\n", mergeRequest.TargetBranch)
				mergeRequestInfo := MergeRequestInfo{
					MergeRequestID: mergeRequest.IID,
					StatusCode:     404,
				}
				projectInfo.MergeRequests = append(projectInfo.MergeRequests, mergeRequestInfo)
				continue
			}
			log.Printf("Branch exists. Creating PR...\n")
			pullRequest, resp, err := createPullRequest(githubClient, owner, dstRepo, mergeRequest)
			statusCode := resp.StatusCode
			mergeRequestInfo := MergeRequestInfo{
				MergeRequestID: mergeRequest.IID,
				StatusCode:     statusCode,
			}
			projectInfo.MergeRequests = append(projectInfo.MergeRequests, mergeRequestInfo)
			time.Sleep(duration)
			if err != nil {
				log.Println(err)
				if strings.Contains(err.Error(), "You have exceeded a secondary rate limit") {
					isRateLimitExceeded = true
				}
			} else {
				labels, err := getMergeRequestLabels(gitlabClient, cast.ToInt(projectID), mergeRequest.IID)
				if err != nil {
					log.Println(err)
				}

				if mergeRequest.State != "opened" {
					_, _, err := closePullRequest(githubClient, owner, dstRepo, pullRequest)
					time.Sleep(duration)
					if err != nil {
						log.Println(err)
						return
					}
				}

				addLabelsToPullRequest(githubClient, owner, dstRepo, pullRequest, labels)
				time.Sleep(duration)

				assignee := ""
				if mergeRequest.Assignee != nil {
					assignee = fmt.Sprintf("[%s](%s/%s)", mergeRequest.Assignee.Username, gitlabURL, mergeRequest.Assignee.Username)
				}

				MergeRequestURL := fmt.Sprintf(gitlabURL+"/%s/%s/-/merge_requests/%d", srcRepoGroup, srcRepoName, mergeRequest.IID)
				comment := ""
				if assignee == "" {
					comment = fmt.Sprintf("Migrated from GitLab.\nAt GitLab was not been assigned\n%s", MergeRequestURL)
				} else {
					comment = fmt.Sprintf("Migrated from GitLab.\nAt GitLab was been assigned to: %s\n%s", assignee, MergeRequestURL)
				}
				_, _, err = githubClient.Issues.CreateComment(context.Background(), owner, dstRepo, pullRequest.GetNumber(), &github.IssueComment{
					Body: github.String(comment),
				})

				time.Sleep(duration)

				if err != nil {
					log.Printf("Error adding comment to pull request %d: %v\n", pullRequest.GetNumber(), err)
				} else {
					log.Printf("Comment added to pull request %d\n", pullRequest.GetNumber())
				}
			}
			continue
		}

		if !state {
			err = writeProgress(projectInfo, progressFilePath)
			if err != nil {
				log.Println(err)
			}
		}
		_, processedMR, err = readProcessedPullRequestsFromFile(progressFilePath)
		if err != nil {
			log.Printf("Can't validate progress file %s", err)
		}

		mrTable = createMRTable(processedMR)
		for statusCode, count := range mrTable {
			fmt.Printf("Status Code %d: %d MR\n", statusCode, count)
		}

		// Получение Issues из Gitlab
		gitlabIssues, _, err := gitlabClient.Issues.ListProjectIssues(projectID, &gitlab.ListProjectIssuesOptions{})
		if err != nil {
			log.Println(err)
		}

		// Взято из chat.openai.com
		// Разворачиваем срез с Issue'ами GitLab для сохранения порядка
		// предполагая, что порядок основан на времени создания, поэтому обрабатываем их от старых к новым
		reverseGitLabIssues(gitlabIssues)

		// Получение Issues из GitHub
		issuesOption := &github.IssueListByRepoOptions{
			State: "all",
			ListOptions: github.ListOptions{
				PerPage: 100, // 100 - доступный максимум
			},
		}

		var allGithubIssues []*github.Issue
		for {
			githubIssues, response, err := githubClient.Issues.ListByRepo(context.Background(), owner, dstRepo, issuesOption)
			if err != nil {
				print(err)
			}
			allGithubIssues = append(allGithubIssues, githubIssues...)

			if response.NextPage == 0 {
				break
			}

			issuesOption.Page = response.NextPage
			time.Sleep(duration)
		}

		time.Sleep(duration)

		// Определение регулярного выражения для отсеивания PR'ов
		pattern := strings.ToLower(fmt.Sprintf("https://github.com/%s/%s/issues/*", regexp.QuoteMeta(owner), regexp.QuoteMeta(dstRepo)))

		// Компиляция регулярного выражения
		regex, err := regexp.Compile(pattern)
		if err != nil {
			fmt.Println("Ошибка при компиляции регулярного выражения:", err)
			return
		}

		// Мапа с Tittle'ами Issus'ов из Github для сравнения
		githubIssueTitles := make(map[string]bool)
		for _, issue := range allGithubIssues {
			if regex.MatchString(strings.ToLower(*issue.HTMLURL)) {
				githubIssueTitles[strings.ToLower(*issue.Title)] = true
			}
		}

		// Получаем содержимое Issues для отправки GitHub
		for _, issue := range gitlabIssues {
			title := issue.Title
			body := issue.Description

			if githubIssueTitles[strings.ToLower(title)] {
				log.Printf("GitHub issue with title '%s' already exists, skipping...\n", title)
				for _, v := range allGithubIssues {
					if strings.ToLower(*v.Title) == strings.ToLower(title) {
						if *v.State != issue.State {
							var issueRequest *github.IssueRequest
							issueRequest = &github.IssueRequest{
								State: &issue.State,
							}
							_, _, err := githubClient.Issues.Edit(context.Background(), owner, dstRepo, *v.Number, issueRequest)
							if err != nil {
								print(err)
							}
						}
					} else {
						continue
					}
				}

				continue
			}

			// Создание GitHub issue
			newIssue := &github.IssueRequest{
				Title: &title,
				Body:  &body,
			}
			createdIssue, _, err := githubClient.Issues.Create(context.Background(), owner, dstRepo, newIssue)
			if err != nil {
				log.Printf("Failed to create GitHub issue for GitLab issue #%d: %v\n", issue.IID, err)
				continue
			}

			if *createdIssue.State != issue.State {
				var issueRequest *github.IssueRequest
				issueRequest = &github.IssueRequest{
					State: &issue.State,
				}
				_, _, err := githubClient.Issues.Edit(context.Background(), owner, dstRepo, *createdIssue.Number, issueRequest)
				if err != nil {
					print(err)
				}
			}

			log.Printf("Successfully migrated GitLab issue #%d to GitHub\n", issue.IID)
		}

		log.Println("Get Gitlab Tags")
		gitlabTags, err := getGitLabTags(projectID, gitlabClient)
		if err != nil {
			log.Fatalf("Failed to get tags from GitLab: %v", err)
		}

		log.Println("Create Github Tags")
		err = createGitHubTags(context.Background(), githubClient, owner, dstRepo, gitlabTags)
		if err != nil {
			log.Fatalf("Failed to create tags in GitHub: %v", err)
		}
		time.Sleep(duration)

		log.Println("Shutdown application")
		if isRateLimitExceeded == true {
			log.Println("NB: not all ur PR might be migrated because u got rate limit. Re-run application later (10-20 min)", err)
		} else {
			log.Println("NB: U have not reached rate limit.", err)
		}
		log.Printf("Target repo: %s", destinationURL)
	},
}

//func init() {
//rootCmd.PersistentFlags().StringVarP(&sourceURL, "source", "s", "", "Required. Source Url. Must be gitlab repo")
//rootCmd.PersistentFlags().StringVarP(&organization, "organization", "o", "", "Opt. Destination Github organization")
//rootCmd.PersistentFlags().StringVarP(&repoName, "repoName", "r", "", "Required. Name of the repository to be created in Github ")
//rootCmd.Flags().StringVarP(&topics, "topics", "t", "", "Opt. Topics (comma-separated)")
//err := rootCmd.MarkPersistentFlagRequired("source")
//if err != nil {
//	log.Println("Pls setup required flags:", err)
//}
//
//}

func main() {

	if err := rootCmd.Execute(); err != nil {
		_, err := fmt.Println(os.Stderr, err)
		if err != nil {
			fmt.Println("Some things fatal(main.cmd):", err)
			return
		}
		if err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

}

func getPAT() string {
	prompt := promptui.Prompt{
		Label: "Enter your github Personal Access Token",
		Validate: func(input string) error {
			if input == "" {
				return errors.New("PAT is required")
			}
			return nil
		},
		Mask: '*',
	}
	ghToken, err := prompt.Run()
	if err != nil {
		panic(err)
	}
	return ghToken
}

func getGLToken() string {
	prompt := promptui.Prompt{
		Label: "Enter your gitlab token",
		Validate: func(input string) error {
			if input == "" {
				return errors.New("gitlab token is required")
			}
			return nil
		},
		Mask: '*',
	}
	glToken, err := prompt.Run()
	if err != nil {
		panic(err)
	}
	return glToken
}

func reverseGitLabIssues(issues []*gitlab.Issue) {
	for i, j := 0, len(issues)-1; i < j; i, j = i+1, j-1 {
		issues[i], issues[j] = issues[j], issues[i]
	}
}

func writeProgress(projectInfo ProjectInfo, progressFilePath string) error {

	if _, err := os.Stat(progressFilePath); err == nil {
		if err := os.Remove(progressFilePath); err != nil {
			log.Printf("Failed to remove existing progress file: %v\n", err)
			return err
		}
	}
	progressJSON, err := json.Marshal(projectInfo)
	if err != nil {
		log.Printf("Failed to marshal progress to JSON: %v\n", err)
		return err
	}

	// Создание файла для записи данных.
	progressFile, err := os.Create(progressFilePath)
	if err != nil {
		log.Printf("Failed to create progress file: %v\n", err)
		return err
	}
	defer progressFile.Close()

	_, err = progressFile.Write(progressJSON)
	if err != nil {
		log.Printf("Failed to write progress to file: %v\n", err)
		return err
	}
	return nil
}

func readProcessedPullRequestsFromFile(filePath string) (int, map[int][]MergeRequestInfo, error) {

	// Чтение файла progress.json
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return 0, nil, err
	}

	// Распарсим JSON в структуру
	var progress ProjectInfo
	if err := json.Unmarshal(data, &progress); err != nil {
		return 0, nil, err
	}

	// Создадим мапу для группировки merge_request по StatusCode
	groupedMRs := make(map[int][]MergeRequestInfo)
	// Группировка merge_request по StatusCode
	for _, mr := range progress.MergeRequests {
		groupedMRs[mr.StatusCode] = append(groupedMRs[mr.StatusCode], mr)
	}
	return progress.ProjectID, groupedMRs, nil
}

func getMergeRequestIDsForStatusCode(groupedMRs map[int][]MergeRequestInfo, statusCode int) []int {
	// Инициализируем пустой слайс для хранения MergeRequestID
	var mergeRequestIDs []int

	// Проверяем, есть ли массив с заданным StatusCode в мапе
	if mrs, ok := groupedMRs[statusCode]; ok {
		// Если есть, перебираем merge_request в этом массиве и добавляем MergeRequestID в слайс
		for _, mr := range mrs {
			mergeRequestIDs = append(mergeRequestIDs, mr.MergeRequestID)
		}
	}

	return mergeRequestIDs
}

func createMRTable(groupedMRs map[int][]MergeRequestInfo) map[int]int {
	mrTable := make(map[int]int)

	// Перебираем мапу сгруппированных MR
	for statusCode, mrs := range groupedMRs {
		// Добавляем в таблицу количество MR для данного статус кода
		mrTable[statusCode] = len(mrs)
	}

	return mrTable
}

func CreateGitHubRepository(githubClient *github.Client, orgName, repoName string) (*github.Repository, *github.Response, error) {
	// Создаем новый репозиторий
	repo := &github.Repository{
		Name:    github.String(repoName),
		Private: github.Bool(true),
	}

	repo, resp, err := githubClient.Repositories.Create(context.Background(), orgName, repo)
	if err != nil {
		return nil, resp, err
	}
	return repo, resp, nil
}

func AddTopicsToRepository(githubClient *github.Client, repo *github.Repository, topics []string) error {

	_, _, err := githubClient.Repositories.ReplaceAllTopics(context.Background(), *repo.Owner.Login, *repo.Name, topics)
	return err
}

func loadConfig(filename string) (Config, error) {
	var config Config
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return config, err
	}

	// Заполнение конфигурации из YAML-файла
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return config, err
	}

	return config, nil
}

func EncodeWithPublicKey(text string, publicKey string) (string, error) {
	// Decode the public key from base64
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return "", err
	}

	// Decode the public key
	var publicKeyDecoded [32]byte
	copy(publicKeyDecoded[:], publicKeyBytes)

	// Encrypt the secret value
	encrypted, err := box.SealAnonymous(nil, []byte(text), (*[32]byte)(publicKeyBytes), rand.Reader)

	if err != nil {
		return "", err
	}
	// Encode the encrypted value in base64
	encryptedBase64 := base64.StdEncoding.EncodeToString(encrypted)

	return encryptedBase64, nil
}
