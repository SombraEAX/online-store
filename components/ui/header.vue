<template lang="pug">
	.header-pad
		.header-error(v-if="error") {{error}}
		.header(ref="header")
			.header-mobile-menu-button(@click="mobileMenuShow")
				span
				span
				span
			nuxt-link.header-logo-wrapper(to="/" title="Home")
				img.header-logo(src="~/assets/images/logo.png")
			.header-links
				nuxt-link.header-link(v-for="link in links" :key="link.url" :to="link.url") {{link.title}}
			.header-placeholder
			.header-contacts
				.header-contact(v-for="contact in contacts") {{contact}}		
			.header-search-button.header-show-form(
				title="Search site" 
				@click="showSearchBox" 
				ref="searchbutton"
			)
			input.header-search-input.alfa(
				placeholder="Enter search query"
				ref="searchInput"
				v-model="query"
			)
			.header-search-button.header-submit.alfa(title="Search" @click="search")
			.header-mobile-menu(:data-visible="mobileMenuVisible ? '' : null")
				nuxt-link.header-mobile-link(v-for="link in links" :key="link.url" :to="link.url") {{link.title}}					
				.header-mobile-menu-close(@click="mobileMenuHide") ×
		.header-searchbox(ref="searchbox")
			input.header-search-input(
				placeholder="Enter search query"
				style="flex:1" 
				ref="mobileSearchInput"
				v-model="query"
			)
			.header-search-button.header-submit(title="Search" @click="search")
	
</template>
<style scoped lang="scss">
.header,.header-searchbox{
	z-index:100
}
.header .header-show-form{
	display:none
}
.header-searchbox{
	display:none
}
.header-search-input{
	height:100%;
	border:0px;
	background:#ddd;
	padding-left:20px;
	padding-right:20px
}
.header-search-button{
	background-image:url('/search.png');
	width:49px;
	height:49px;
	background-size:50%;
	background-repeat:no-repeat;
	background-position:center;
	cursor:pointer
}
.header-search-button:hover{
	filter:invert(1);
	background-color:#ffff99
}
.header-submit{
	background-color:#ddd !important
}
.header-pad{
	height:50px
}	
.header-mobile-menu{
	position:fixed;
	top:0px;
	bottom:0px;
	left:0px;
	right:0px;
	background:#000;
	padding-top:15px;
	display:none
}
.header-logo-wrapper{
	margin-left:20px;
	margin-right:20px;
	display:flex
}
.header-mobile-menu[data-visible]{
	display:block
}
.header-mobile-menu-close{
	position:fixed;
	right:0px;
	top:0px;
	font-size:50px;
	line-height:50px;
	width:50px;
	height:50px;
	color:#fff;
	text-align:center
}
.header-mobile-link{
	color:#fff;
	text-decoration:none;
	padding-left:30px;
	padding-top:15px;
	padding-bottom:15px;
	display:block
}
.header-mobile-menu-button{
	font-size:36px;
	box-sizing:border-box;
	height:50px;
	width:50px;
	display:flex;
	flex-direction:column;
	align-items:center;
	justify-content:center;
	gap:5px;
	color:#666;
	display:none;
	cursor:pointer
}
.header-mobile-menu-button span{
	display:block;
	width:22px;
	height:2px;
	background:#666;
	border-radius:1px
}
.header-logo{
	height:35px;
	margin:auto
}
.header-placeholder{
	flex:1
}
.header-contacts{
	display:flex;
	margin-right:10px
}
.header-contact{
	margin-left:20px;
	margin-right:0px		
}
.header,.header-searchbox{
	height:50px;
	box-sizing:border-box;
	border-bottom:1px solid #ccc;
	align-items:center;
	position:fixed;
	left:0px;
	right:0px;
	top:0px;
	background:#fff
}
.header{
	display:flex;
}
.header-a{
	display:none
}
.header-link{
	margin-left:7px;
	margin-right:7px;
	color:#888;
	text-decoration:none
}
.header-link:hover{
	text-decoration:underline		
}
@media (max-width: 1030px) {
	.header-contacts{
		display:none
	}
}
@media (max-width:800px){
		.alfa{display:none}
		.header-show-form{
			display:block !important
		}
}
@media (max-width:500px){
	.header-links{
		display:none
	}
	.header-mobile-menu-button{
		display:flex
	}
	.header-logo{
		margin-left:5px
	}
	.header-logo-wrapper{
		margin-left:0px
	}
}
.header-error{
	position:fixed;
	top:60px;
	width:80vw;
	left:10vw;
	background:#000;
	color:#fff;
	border-radius:5px;
	font-size:14px;
	padding:10px
}
</style>
<script>
	export default {
		data(){
			return {
				links: [
					{url:'/',title:'Home'},
					{url:'/catalog/',title:'Catalog'},
					{url:'/contacts',title:'Contacts'}
				],
				error: null,
				contacts:[
					'+1 (555) 123-4567',
					'info@company.com'
				],
				mobileMenuVisible: false,
				query: ''
			}
		},
		mounted(){
			const {
				searchbox,
				searchbutton,
				mobileSearchInput,
				searchInput
			} = this.$refs

			let url = document.location.href

			mobileSearchInput.addEventListener('keydown', event => {
				if(event.key === 'Escape') return this.hideSearchBox()
			})

			mobileSearchInput.addEventListener('keydown', event => this.enterPressHandler(event))
			searchInput.addEventListener('keydown', event => this.enterPressHandler(event))

			let handler = event => {
				const path = event.composedPath()
				const withinBoundaries = path.includes(searchbox) || path.includes(searchbutton)
				
				if(!withinBoundaries) this.hideSearchBox()				
			}

			document.addEventListener('click', handler)

			let timer = setInterval(()=>{
				if(url != document.location.href)
					document.removeEventListener('click', handler),
					clearInterval(timer)
			},500)

			this._clickHandler = handler
			this._timer = timer
		},
		beforeDestroy(){
			document.removeEventListener('click', this._clickHandler)
			clearInterval(this._timer)
		},
		methods:{
			enterPressHandler(event){
				if(event.key === 'Enter') return this.search()				
			},
			mobileMenuShow(){
				this.mobileMenuVisible = true
			},
			mobileMenuHide(){
				this.mobileMenuVisible = false				
			},
			showSearchBox(){
				this.query = ''
				if(this.$refs.header) this.$refs.header.style.display = 'none'				
				if(this.$refs.searchbox) this.$refs.searchbox.style.display = 'flex'				
				if(this.$refs.mobileSearchInput) this.$refs.mobileSearchInput.focus()
			},
			hideSearchBox(){
				if(this.$refs.header) this.$refs.header.style.display = 'flex'				
				if(this.$refs.searchbox) this.$refs.searchbox.style.display = 'none'								
				this.query = ''
			},
			search(){
				if(this.query) return this.$router.push('/search/' + this.query + '/1')

				this.error = 'Empty search query'

				setTimeout(()=> this.error = null, 3000)
			}
		}
	}
</script>
