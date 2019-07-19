#!/usr/bin/env python3

import argparse
import github
import json
import re
import sys
import ssdeep
import sre_constants
import os.path


SIMILARITY_THRESHOLD = 65
ACCESS_TOKEN = "<NO-PERMISSION-GITHUB-TOKEN-HERE>"


class bcolors:
    """ Thank you Blender scripts :) """
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    CLEAR = '\x1b[2J'


class State:

    def __init__(self,
                 bad_users=[],
                 bad_repos=[],
                 bad_files=[],
                 bad_signatures=[],
                 checks=[],
                 lastInitIndex=0,
                 index=0,
                 totalCount=0,
                 query=None,
                 logfile="",
                 ):
        self.bad_users = bad_users
        self.bad_repos = bad_repos
        self.bad_files = bad_files
        self.bad_signatures = bad_signatures
        self.checks = checks
        self.lastInitIndex = lastInitIndex
        self.index = index
        self.totalCount = totalCount
        self.query = query
        self.logfile = logfile


def save_state(name, repositories, state):
    filename = state.logfile.replace("log", "state")
    if name == "ratelimited":
        filename += ".ratelimited"
    with open(filename, "w") as fd:
        json.dump(state.__dict__, fd)
    print("Saved as [{}]".format(filename))


def regex_search(checks, repo):
    output = ""
    for line in repo.decoded_content.splitlines():
        for check in checks:
            try:
                line = line.decode('utf-8')
            except AttributeError:
                pass

            try:
                (line, inst) = re.subn(
                    check,
                    bcolors.BOLD + bcolors.OKBLUE + r'\1' + bcolors.ENDC,
                    line)
                if inst > 0:
                    output += "\t" + line + "\n"
                    print("\t", line)
                    break
            except Exception as e:
                print(e)
    print(bcolors.HEADER + "End of Matches" + bcolors.ENDC)
    return output


def should_parse(repo, state):
    if repo.repository.owner.login in state.bad_users:
        print(bcolors.FAIL + "Failed check: Ignore User" + bcolors.ENDC)
        return False
    if repo.repository.name in state.bad_repos:
        print(bcolors.FAIL + "Failed check: Ignore Repo" + bcolors.ENDC)
        return False
    if repo.name in state.bad_files:
        print(bcolors.FAIL + "Failed check: Ignore File" + bcolors.ENDC)
        return False

    # Fuzzy Hash Comparison
    try:
        candidate_sig = ssdeep.hash(repo.decoded_content)
        for sig in state.bad_signatures:
            similarity = ssdeep.compare(candidate_sig, sig)
            if similarity > SIMILARITY_THRESHOLD:
                print(
                    bcolors.FAIL +
                    "Failed check: Ignore Fuzzy Signature on Contents "
                    "({}% Similarity)".format(similarity) +
                    bcolors.ENDC)
                return False
    except github.UnknownObjectException:
        print(
            bcolors.FAIL +
            "API Error: File no longer exists on github.com" +
            bcolors.ENDC)
        return False
    return True


def print_handler(contents):
        try:
            contents = contents.decode('utf-8')
        except AttributeError:
            pass
        finally:
            print(contents)

        print(contents)


def input_handler(state):
    return input(
        bcolors.HEADER +
        "(Result {}/{})".format(
            state.index +
            1,
            state.totalCount if state.totalCount < 1000 else "1000+") +
        "=== " + bcolors.ENDC +
        "Ignore similar [c]ontents/" +
        bcolors.OKGREEN + "[u]ser/" +
        bcolors.OKBLUE + "[r]epo/" +
        bcolors.WARNING + "[f]ilename" +
        bcolors.HEADER +
        ", [p]rint contents, [s]ave state, [a]dd to log, "
        "search [/(findme)], [b]ack, [q]uit, next [<Enter>]===: " +
        bcolors.ENDC)


def pagination_hack(repositories, state):
    count = len(repositories.__dict__["_PaginatedListBase__elements"])
    if state.index >= count:
        n_elements = repositories.get_page(state.index//30)
        repositories.__dict__["_PaginatedListBase__elements"] += n_elements
    return repositories


def regex_handler(choice, repo):
    if choice[1] != "(" or choice[-1] != ")":
        print(
            bcolors.FAIL +
            "Regex requires at least one group reference: "
            "e.g., (CaSeSensitive) or ((?i)insensitive)" +
            bcolors.ENDC)
        return ""
    else:
        print(bcolors.HEADER + "Searching: " + choice[1:] + bcolors.ENDC)
        return regex_search([choice[1:]], repo)


def ui_loop(repo, repositories, log_buf, state):
    choice = input_handler(state)

    if choice == "c":
        state.bad_signatures.append(ssdeep.hash(repo.decoded_content))
    elif choice == "u":
        state.bad_users.append(repo.repository.owner.login)
    elif choice == "r":
        state.bad_repos.append(repo.repository.name)
    elif choice == "f":
        state.bad_files.append(repo.name)
    elif choice == "p":
        print_handler(repo.decoded_content)
        ui_loop(repo, repositories, log_buf, state)
    elif choice == "s":
        save_state(state.query, repositories, state)
        ui_loop(repo, repositories, log_buf, state)
    elif choice == "a":
        with open(state.logfile, "a") as fd:
            fd.write(log_buf)
    elif choice.startswith("/"):
        log_buf += regex_handler(choice, repo)
        ui_loop(repo, repositories, log_buf, state)
    elif choice == "b":
        if state.index - 1 < state.lastInitIndex:
            print(
                bcolors.FAIL +
                "Can't go backwards past restore point "
                "because of rate-limiting/API limitations" +
                bcolors.ENDC)
            ui_loop(repo, repositories, log_buf, state)
        else:
            state.index -= 2
    elif choice == "q":
        sys.exit(0)


def api_request_loop(state):
    g = github.Github(ACCESS_TOKEN)

    print("Collecting Github Search API data...")
    try:
        repositories = g.search_code(state.query)

        state.totalCount = repositories.totalCount

        # Hack to backfill PaginatedList with garbage to avoid ratelimiting on
        # restore, library fetches in 30 counts
        repositories.__dict__["_PaginatedListBase__elements"] = [
            None] * (state.index//30) * 30
        state.lastInitIndex = state.index

        print(bcolors.CLEAR)

        i = state.index
        stepBack = False
        while i < state.totalCount:
            while True:
                try:
                    state.index = i

                    # Manually fill Paginator to avoid ratelimiting on restore
                    repositories = pagination_hack(repositories, state)

                    repo = repositories[i]

                    log_buf = "https://github.com/" + \
                        bcolors.OKGREEN + repo.repository.owner.login + "/" + \
                        bcolors.OKBLUE + repo.repository.name + "/blob" + \
                        bcolors.ENDC + \
                        os.path.dirname(repo.html_url.split('blob')[1]) + \
                        "/" + bcolors.WARNING + repo.name + bcolors.ENDC
                    print(log_buf)
                    log_buf = "\n" + log_buf + "\n"

                    if should_parse(repo, state) or stepBack:
                        stepBack = False
                        log_buf += regex_search(state.checks, repo)
                        ui_loop(repo, repositories, log_buf, state)
                        if state.index < i:
                            i = state.index
                            stepBack = True
                        print(bcolors.CLEAR)
                    else:
                        print("Skipping...")
                    i += 1
                    break
                except github.RateLimitExceededException:
                    try:
                        print(
                            bcolors.FAIL +
                            "RateLimitException: "
                            "Please wait about 30 seconds before you "
                            "try again, or exit (CTRL-C).\n " +
                            bcolors.ENDC)
                        save_state("ratelimited", repositories, state)
                        input("Press enter to try again...")
                    except KeyboardInterrupt:
                        sys.exit(1)
    except github.RateLimitExceededException:
        print(
            bcolors.FAIL +
            "RateLimitException: "
            "Please wait about 30 seconds before you try again.\n" +
            bcolors.ENDC)
        save_state("ratelimited", repositories, state)
        sys.exit(-1)


def regex_validator(args, state):
    with open(args.checks, "r") as fd:
        for line in fd.read().splitlines():
            if line.startswith("#") or len(line) == 0:
                continue
            try:
                re.subn(line, r'\1', "Expression test")
            except sre_constants.error as e:
                print(bcolors.FAIL + "Invalid Regular expression:\n\t" + line)
                if "group" in str(e):
                    print(
                        "Ensure expression contains"
                        "a capture group for matches:\n\t" + str(e))
                sys.exit(-1)
            state.checks.append(line)

    escaped_query = state.query.replace("(", "\\(").replace(")", "\\)")
    state.checks.append("(?i)(" + escaped_query + ")")
    return state


def main():
    if sys.version_info < (3, 0):
        sys.stdout.write("Sorry, requires Python 3.x, not Python 2.x\n")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="./" + sys.argv[0] + " -q example.com\n" +
        "./" + sys.argv[0] + " -q example.com -f checks/default.list "
        "-o example1.log\n" +
        "./" + sys.argv[0] + " -q example.com -r example.com.state")
    parser.add_argument(
        "-q",
        "--query",
        help="Github Code Query",
        type=str,
        required=True)
    parser.add_argument(
        "-f",
        "--checks",
        help="List of RegEx checks (checks/default.list)",
        type=str,
        default="checks/default.list")
    parser.add_argument(
        "-o",
        "--output",
        help="Log name (default: <query>.log)",
        type=str)
    parser.add_argument(
        "-r",
        "--recover",
        help="Name of recovery file",
        type=str)
    args = parser.parse_args()

    state = State()
    state.index = 0

    if ACCESS_TOKEN == "<NO-PERMISSION-GITHUB-TOKEN-HERE>":
        print("Github Access token not set")
        sys.exit(1)

    if args.recover:
        with open(args.recover, 'r') as fd:
            state = State(**json.load(fd))

    args.query = args.query.lstrip()

    # Reusing Blacklists on new query
    if state.query != args.query:
        state.query = args.query
        state.index = 0

    if args.output:
        state.logfile = args.output
    else:
        state.logfile = "logs/" + \
            re.sub(r"[,.;@#?!&$/\\]+\ *", "_", args.query) + ".log"

    # Create default directories if they don't exist
    try:
        os.mkdir("logs")
        os.mkdir("states")
    except FileExistsError:
        pass

    # Load/Validate RegEx Checks
    state = regex_validator(args, state)

    api_request_loop(state)


if __name__ == "__main__":
    main()
