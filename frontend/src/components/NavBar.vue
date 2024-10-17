<template>
    <nav class="navbar">
        <div class="title"> <RouterLink to="/overview">價格追蹤小幫手</RouterLink></div>
        <div class="hamburger" id="hamburger" @click="make_menu_thin"> &#9776;</div>
        <ul class="options" ref="navMenu">
            <li><RouterLink to="/overview">物價概覽</RouterLink></li>
            <li><RouterLink to="/trending">物價趨勢</RouterLink></li>
            <li><RouterLink to="/news">相關新聞</RouterLink></li>
            <li v-if="!isLoggedIn"><RouterLink to="/login">登入</RouterLink></li>
            <li v-else @click="logout">Hi, {{getUserName}}! 登出</li>
        </ul>
    </nav>
</template>


<script>
import { useAuthStore } from '@/stores/auth';

export default {
    name: 'NavBar',
    computed: {
        isLoggedIn(){
            const userStore = useAuthStore();
            return userStore.isLoggedIn;
        },
        getUserName(){
            const userStore = useAuthStore();
            return userStore.getUserName;
        }
    },
    methods: {
        logout(){
            const userStore = useAuthStore();
            userStore.logout();
        },
        make_menu_thin(){
            const navMenu = this.$refs.navMenu;
            navMenu.classList.toggle("active");
        }
    }
};
</script>

<style scoped>
.navbar {
    display: flex;
    justify-content: space-between;
    background-color: #f3f3f3;
    padding: 1.5em;
  /*  height: 4.5em;*/
    width: 100%;
    align-items: center;
    box-shadow: 0 0 5px #000000;
}

.navbar ul {
    list-style: none;
    display: flex;
    justify-content: space-around;
}

.title > a{
    font-size: 1.4em;
    font-weight: bold;
    color: #2c3e50 !important;
}

.navbar li {
    color: #575B5D;
    margin: 0 .5em;
    font-size: 1.2em;
}

.navbar li:hover{
    cursor: pointer;
    font-weight: bold;
}

.navbar a {
    text-decoration: none;
    color: #575B5D;
}

.hamburger {
    display: none;
    font-size: 1.2em;
    cursor: pointer;
    position: absolute;
    right: 0;
    user-select: none;
}

@media (max-width: 768px) {
    .navbar {
        flex-direction: column;
        align-items: center;
    }

    .navbar ul {
        display: none;
        flex-direction: column;
        width: 100%;
        background-color: #f3f3f3;
    }

    .hamburger {
        display: block;
        display: flex;
    }

    .navbar ul.active {
        display: flex;
    }
}
</style>



